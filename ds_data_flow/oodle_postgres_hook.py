

import os
import boto3
import random
import numpy as np
from time import sleep
from typing import Generator

import psycopg2
import logging
import psycopg2.extensions
from contextlib import closing
from .secrets_manager import SecretsManager
from datetime import datetime
from urllib.parse import quote_plus, urlunsplit

# from oodle.utils.xray import XRay
from aws_xray_sdk.core import xray_recorder
xray_recorder.configure(context_missing='LOG_ERROR')
logging.getLogger('aws_xray_sdk').setLevel(logging.CRITICAL)


class OodlePostgresHook:
    """
    Interact with Postgres.
    You can specify ssl parameters in the extra field of your connection
    as ``{"sslmode": "require", "sslcert": "/path/to/cert.pem", etc}``.

    Note: For Redshift, use keepalives_idle in the extra connection parameters
    and set it to less than 300 seconds.

    Note: For AWS IAM authentication, use iam in the extra connection parameters
    and set it to true. Leave the password field empty. This will use the the
    "aws_default" connection to get the temporary token unless you override
    in extras.
    extras example: ``{"iam":true, "aws_conn_id":"my_aws_conn"}``
    For Redshift, also use redshift in the extra connection parameters and
    set it to true. The cluster-identifier is extracted from the beginning of
    the host field, so is optional. It can however be overridden in the extra field.
    extras example: ``{"iam":true, "redshift":true, "cluster-identifier": "my_cluster_id"}``
    """
    conn_name_attr = 'postgres_conn_id'
    default_conn_name = 'postgres_default'
    supports_autocommit = True

    def __init__(self, secret_name=None, null_string='nan', manager=None, *args, **kwargs):
        self.schema = kwargs.get("schema", None)
        self.null_string = null_string

        self.aws_profile_name = kwargs.get("aws_profile_name", None)
        self.dsn_initial = kwargs.get("dsn", None)
        self.dsn = kwargs.get("dsn", None)
        self.manager = manager
        self.secret_name = secret_name

    @xray_recorder.capture()
    def generate_dsn(self):
        if self.manager is None:
            self.manager = SecretsManager(profile_name=self.aws_profile_name)

        secret = self.manager.get_secret(self.secret_name)

        # check for authentication via AWS IAM
        if secret.get('iam', False):
            login, password, port = self.get_iam_token(secret)
            self.dsn = {
                "host": secret.get("host", "localhost"),
                "user": login,
                "password": password,
                "dbname": self.schema or secret.get("dbname") or "",
                "port": port if port else 5432
            }
        else:
            self.dsn = {
                "host": secret.get("host", "localhost"),
                "user": secret.get("username"),
                "password": secret.get("password", ""),
                "dbname": self.schema or secret.get("dbname") or "",
                "port": int(secret.get("port", 5432))
            }

        for arg_name, arg_val in secret.items():
            if arg_name in [
                'sslmode',
                'sslcert',
                'sslkey',
                'sslrootcert',
                'sslcrl',
                'application_name',
                'keepalives_idle'
            ]:

                self.dsn[arg_name] = arg_val

    @xray_recorder.capture()
    def get_conn(self):
        # If the DSN is not specified, keep regenerating it
        # This is needed for IAM authentication
        if self.dsn_initial is None:
            self.generate_dsn()

        attempts = 0
        while True:
            try:
                conn = psycopg2.connect(**self.dsn)
                # print('Connection established')
                break
            except psycopg2.Error as e:
                attempts += 1
                sleep(2)
                if attempts > 3:
                    raise e
                print(f'Retrying Postgres connection {attempts}/3')
        self.conn = conn
        return self.conn

    @xray_recorder.capture()
    def copy_expert(self, sql, filename, open=open):
        """
        Executes SQL using psycopg2 copy_expert method.
        Necessary to execute COPY command without access to a superuser.

        Note: if this method is called with a "COPY FROM" statement and
        the specified input file does not exist, it creates an empty
        file and no data is loaded, but the operation succeeds.
        So if users want to be aware when the input file does not exist,
        they have to check its existence by themselves.
        """

        with open(filename, 'r+') as f:
            with closing(self.get_conn()) as conn:
                with closing(conn.cursor()) as cur:
                    cur.copy_expert(sql, f)
                    f.truncate(f.tell())
                    conn.commit()

    @xray_recorder.capture()
    def bulk_load(self, table, tmp_file, fmt="text", header="false", delimiter='\t'):
        """
        Loads a tab-delimited file into a database table.
        DOES NOT WORK WITH REDSHIFT!
        """
        null_string = self.null_string
        if not null_string:
            null_string = r'\N'

        query = "COPY {table} FROM STDIN WITH (NULL '{null_string}', FORMAT {fmt}, HEADER {header}, DELIMITER '{delimiter}')".format(
            table=table, null_string=null_string, fmt=fmt, header=header, delimiter=delimiter)

        logging.info("bulk_load")
        logging.info(query)
        self.copy_expert(query, tmp_file)

    @xray_recorder.capture()
    def bulk_dump(self, table, tmp_file):
        """
        Dumps a database table into a tab-delimited file
        """
        self.copy_expert(
            "COPY {table} TO STDOUT".format(table=table), tmp_file)

    @staticmethod
    def _serialize_cell(cell, conn):
        """
        Postgresql will adapt all arguments to the execute() method internally,
        hence we return cell without any conversion.

        See http://initd.org/psycopg/docs/advanced.html#adapting-new-types for
        more information.

        :param cell: The cell to insert into the table
        :type cell: object
        :param conn: The database connection
        :type conn: connection object
        :return: The cell
        :rtype: object
        """
        return cell

    @xray_recorder.capture()
    def get_iam_token(self, secret):
        """
        Uses AWSHook to retrieve a temporary password to connect to Postgres
        or Redshift. Port is required. If none is provided, default is used for
        each service
        """
        host = secret.get('host')
        redshift = 'redshift' in host
        session = boto3.Session(profile_name=self.aws_profile_name)

        # If no username is in the secret, choose dynamically based on caller identity which username to use
        if secret.get("username", None):
            login = secret.get("username")
        else:
            client = session.client('sts', region_name='eu-west-1')
            caller_identity = client.get_caller_identity()
            user_id = caller_identity['UserId']
            if '@oodlefinance.com' in user_id:
                login = user_id.split(":")[1].lower()
            elif 'JHubIAMRole' in user_id:
                login = 'loanorigination_user'
            else:
                login = 'airflow_user'
        port = int(secret.get("port", 5432))
        if redshift:
            # Pull the custer-identifier from the beginning of the Redshift URL
            # ex. my-cluster.ccdre4hpd39h.us-east-1.redshift.amazonaws.com returns my-cluster
            cluster_identifier = host.split('.')[0]
            client = session.client('redshift', region_name='eu-west-1')
            cluster_creds = client.get_cluster_credentials(
                DbUser=login,
                DbName=self.schema or secret.get("dbname") or "",
                ClusterIdentifier=cluster_identifier,
                AutoCreate=False,
                DurationSeconds=3600)
            token = cluster_creds['DbPassword']
            login = cluster_creds['DbUser']
        else:
            client = session.client('rds', region_name='eu-west-1')
            token = client.generate_db_auth_token(host, port, login)
        return login, token, port

    @xray_recorder.capture()
    def query_results_generator(self, query: str, params=None, cursor_factory=None) -> Generator:
        """
        This function returns generator over query's result set. It keeps memory footprint low by using
        server-side cursor.
        """
        with closing(self.get_conn()) as conn:
            with closing(conn.cursor(name='query_res_{0}'.format(random.randint(0, 9999999999999)),
                                     cursor_factory=cursor_factory)) as cur:
                cur.execute(query, params)
                for rec in cur:
                    yield rec

    @xray_recorder.capture("pghook_get_pandas_df")
    def get_pandas_df(self, sql, parameters = None, *args, **kwargs):
        document = xray_recorder.current_subsegment()
        if document is not None:
            document.put_annotation("query", sql)
        from pandas.io import sql as psql

        with closing(self.get_conn()) as conn:
            return psql.read_sql(sql, con=conn, params=parameters, **kwargs)

    @xray_recorder.capture("pghook_extract_table_paged_generator")
    def extract_table_paged_generator(self, table_name, chunk_on, page_size, parameters=None, ):
        # this has to be paged because we
        chunk_size = 100_000
        min_id, max_id = self.get_pandas_df(
            f"""
        select min({chunk_on}), max({chunk_on}) from
        {table_name}
        """
        ).iloc[0]
        chunks = int(np.ceil((max_id - min_id) / chunk_size)) + 1

        df_generator = (self.get_pandas_df(f"""
        select *
        from {table_name}
        where {chunk_on} >= ({min_id} + ({i} * {chunk_size}))
                and {chunk_on} < ({min_id} + ({i} + 1 )* {chunk_size})

        """) for i in range(chunks))

        return df_generator


    # CODE CLONED FROM AIRFLOW
    def get_uri(self) -> str:
        """
        Extract the URI from the connection.
        :return: the extracted uri.
        """
        conn = self.get_connection(getattr(self, self.conn_name_attr))
        login = ''
        if conn.login:
            login = f'{quote_plus(conn.login)}:{quote_plus(conn.password)}@'
        host = conn.host
        if conn.port is not None:
            host += f':{conn.port}'
        schema = self.__schema or conn.schema or ''
        return urlunsplit((conn.conn_type, f'{login}{host}', schema, '', ''))

    def get_records(self, sql, parameters=None):
        """
        Executes the sql and returns a set of records.
        :param sql: the sql statement to be executed (str) or a list of
            sql statements to execute
        :type sql: str or list
        :param parameters: The parameters to render the SQL query with.
        :type parameters: dict or iterable
        """
        with closing(self.get_conn()) as conn:
            with closing(conn.cursor()) as cur:
                if parameters is not None:
                    cur.execute(sql, parameters)
                else:
                    cur.execute(sql)
                return cur.fetchall()

    def get_first(self, sql, parameters=None):
        """
        Executes the sql and returns the first resulting row.
        :param sql: the sql statement to be executed (str) or a list of
            sql statements to execute
        :type sql: str or list
        :param parameters: The parameters to render the SQL query with.
        :type parameters: dict or iterable
        """
        with closing(self.get_conn()) as conn:
            with closing(conn.cursor()) as cur:
                if parameters is not None:
                    cur.execute(sql, parameters)
                else:
                    cur.execute(sql)
                return cur.fetchone()

    @xray_recorder.capture("pghook_run")
    def run(self, sql, autocommit=False, parameters=None, handler=None):
        """
        Runs a command or a list of commands. Pass a list of sql
        statements to the sql parameter to get them to execute
        sequentially
        :param sql: the sql statement to be executed (str) or a list of
            sql statements to execute
        :type sql: str or list
        :param autocommit: What to set the connection's autocommit setting to
            before executing the query.
        :type autocommit: bool
        :param parameters: The parameters to render the SQL query with.
        :type parameters: dict or iterable
        :param handler: The result handler which is called with the result of each statement.
        :type handler: callable
        :return: query results if handler was provided.
        """
        scalar = isinstance(sql, str)
        if scalar:
            sql = [sql]

        with closing(self.get_conn()) as conn:
            if self.supports_autocommit:
                self.set_autocommit(conn, autocommit)

            with closing(conn.cursor()) as cur:
                results = []
                for sql_statement in sql:
                    self._run_command(cur, sql_statement, parameters)
                    if handler is not None:
                        result = handler(cur)
                        results.append(result)

            # If autocommit was set to False for db that supports autocommit,
            # or if db does not supports autocommit, we do a manual commit.
            if not self.get_autocommit(conn):
                conn.commit()

        if handler is None:
            return None

        if scalar:
            return results[0]

        return results

    def _run_command(self, cur, sql_statement, parameters):
        """Runs a statement using an already open cursor."""
        print("Running statement: %s, parameters: %s", sql_statement, parameters)
        if parameters:
            cur.execute(sql_statement, parameters)
        else:
            cur.execute(sql_statement)

        # According to PEP 249, this is -1 when query result is not applicable.
        if cur.rowcount >= 0:
            print("Rows affected: %s", cur.rowcount)

    def set_autocommit(self, conn, autocommit):
        """Sets the autocommit flag on the connection"""
        if not self.supports_autocommit and autocommit:
            print(
                "%s connection doesn't support autocommit but autocommit activated.",
                getattr(self, self.conn_name_attr),
            )
        conn.autocommit = autocommit

    def get_autocommit(self, conn):
        """
        Get autocommit setting for the provided connection.
        Return True if conn.autocommit is set to True.
        Return False if conn.autocommit is not set or set to False or conn
        does not support autocommit.
        :param conn: Connection to get autocommit setting from.
        :type conn: connection object.
        :return: connection autocommit setting.
        :rtype: bool
        """
        return getattr(conn, 'autocommit', False) and self.supports_autocommit

    def get_cursor(self):
        """Returns a cursor"""
        return self.get_conn().cursor()

    @staticmethod
    def _generate_insert_sql(table, values, target_fields, replace, **kwargs):
        """
        Static helper method that generate the INSERT SQL statement.
        The REPLACE variant is specific to MySQL syntax.
        :param table: Name of the target table
        :type table: str
        :param values: The row to insert into the table
        :type values: tuple of cell values
        :param target_fields: The names of the columns to fill in the table
        :type target_fields: iterable of strings
        :param replace: Whether to replace instead of insert
        :type replace: bool
        :return: The generated INSERT or REPLACE SQL statement
        :rtype: str
        """
        placeholders = [
            "%s",
        ] * len(values)

        if target_fields:
            target_fields = ", ".join(target_fields)
            target_fields = f"({target_fields})"
        else:
            target_fields = ''

        if not replace:
            sql = "INSERT INTO "
        else:
            sql = "REPLACE INTO "
        sql += f"{table} {target_fields} VALUES ({','.join(placeholders)})"
        return sql

    def insert_rows(self, table, rows, target_fields=None, commit_every=1000, replace=False, **kwargs):
        """
        A generic way to insert a set of tuples into a table,
        a new transaction is created every commit_every rows
        :param table: Name of the target table
        :type table: str
        :param rows: The rows to insert into the table
        :type rows: iterable of tuples
        :param target_fields: The names of the columns to fill in the table
        :type target_fields: iterable of strings
        :param commit_every: The maximum number of rows to insert in one
            transaction. Set to 0 to insert all rows in one transaction.
        :type commit_every: int
        :param replace: Whether to replace instead of insert
        :type replace: bool
        """
        i = 0
        with closing(self.get_conn()) as conn:
            if self.supports_autocommit:
                self.set_autocommit(conn, False)

            conn.commit()

            with closing(conn.cursor()) as cur:
                for i, row in enumerate(rows, 1):
                    lst = []
                    for cell in row:
                        lst.append(self._serialize_cell(cell, conn))
                    values = tuple(lst)
                    sql = self._generate_insert_sql(table, values, target_fields, replace, **kwargs)
                    cur.execute(sql, values)
                    if commit_every and i % commit_every == 0:
                        conn.commit()
                        print("Loaded %s rows into %s so far", i, table)

            conn.commit()
        print("Done loading. Loaded a total of %s rows", i)

    @staticmethod
    def _serialize_cell(cell, conn=None):
        """
        Returns the SQL literal of the cell as a string.
        :param cell: The cell to insert into the table
        :type cell: object
        :param conn: The database connection
        :type conn: connection object
        :return: The serialized cell
        :rtype: str
        """
        if cell is None:
            return None
        if isinstance(cell, datetime):
            return cell.isoformat()
        return str(cell)

    def test_connection(self):
        """Tests the connection by executing a select 1 query"""
        status, message = False, ''
        try:
            with closing(self.get_conn()) as conn:
                with closing(conn.cursor()) as cur:
                    cur.execute("select 1")
                    if cur.fetchone():
                        status = True
                        message = 'Connection successfully tested'
        except Exception as e:
            status = False
            message = str(e)

        return status, message

if __name__ == "__main__":
    from oodle import config

    pg_hook = OodlePostgresHook(secret_name=config.REDSHIFT_SECRET)
    df = pg_hook.get_pandas_df("SELECT 1 as test")
    df = pg_hook.run("SELECT 1 as test")
    print("test")
    i = 9
