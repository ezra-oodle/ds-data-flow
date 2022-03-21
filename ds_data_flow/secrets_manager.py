"""
Oodle Secrets Manager Class

Special Features:
    - Supports "proxy secrets" to access secrets from other AWS accounts.
      These work by assuming an IAM role in another account, creating a secrets manager client in that other account, then retrieving the secret.
      This process is documented in: https://oodlefinance.atlassian.net/wiki/spaces/DATA/pages/3010035920/Database+secrets+in+AWS+Risk under "production secrets"

"""

# If you need more information about configurations or implementing the sample code, visit the AWS docs:
# https://aws.amazon.com/developers/getting-started/python/
import base64
import json
from typing import Optional

import boto3
from botocore.exceptions import ClientError


class SecretsManager:

    def __init__(self,
                 aws_access_key_id: Optional[str] = None,
                 aws_secret_access_key: Optional[str] = None,
                 aws_session_token: Optional[str] = None,
                 profile_name: Optional[str] = None,
                 keys_from_secret: Optional[str] = None,
                 region_name: str = "eu-west-1"):
        """
        Initializes SecretManager. Under the hood creates session client that talks to AWS's Secret Manager.
        The client can be authenticated towards AWS using 4 different options defined by input arguments:
        - by providing aws_access_key_id, aws_secret_access_key pair
        - by providing profile_name
        - by providing keys_from_secret, in this case the client will use a pair of
          (aws_access_key_id, aws_secret_access_key) derived from secret with a name <keys_from_secret>
        - by not providing anything...
        """

        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_session_token = aws_session_token

        self.profile_name = profile_name

        self.keys_from_secret = keys_from_secret

        self.region_name = region_name
        self.client = None

        # validate input arguments
        if self.aws_secret_access_key is None and self.aws_access_key_id is not None:
            raise ValueError(
                'Either both aws_secret_access_key and aws_access_key_id or none of them can be None')
        if self.aws_access_key_id is None and self.aws_secret_access_key is not None:
            raise ValueError(
                'Either both aws_secret_access_key and aws_access_key_id or none of them can be None')

        if int(self.aws_secret_access_key is not None) + int(self.profile_name is not None) + int(
                self.keys_from_secret is not None) > 1:
            raise ValueError(
                'Config (aws_access_key_id, aws_secret_access_key)/profile_name/keys_from_secret is mutually exclusive. Provide only one value.')

    def _init_client(self):
        if self.keys_from_secret is not None:
            remote_aws_iam_temporary_credentials = self.get_temporary_access_credentials_from_assume_role(
                assume_iam_role=self.keys_from_secret)
            session = boto3.session.Session(aws_access_key_id=remote_aws_iam_temporary_credentials['AccessKeyId'],
                                            aws_secret_access_key=remote_aws_iam_temporary_credentials[
                                                'SecretAccessKey'],
                                            aws_session_token=remote_aws_iam_temporary_credentials['SessionToken'])
        elif self.aws_access_key_id is not None:
            session = boto3.session.Session(aws_access_key_id=self.aws_access_key_id,
                                            aws_secret_access_key=self.aws_secret_access_key,
                                            aws_session_token=self.aws_session_token)
        elif self.profile_name is not None:
            session = boto3.session.Session(profile_name=self.profile_name)
        else:

            session = boto3.session.Session()

        # Create a Secrets Manager client
        self.client = session.client(
            service_name='secretsmanager',
            region_name=self.region_name
        )

    def get_temporary_access_credentials_from_assume_role(self, assume_iam_role):
        print(f"Retrieving credentials by assuming role: {assume_iam_role}")
        remote_aws_assumed_role = boto3.client('sts').assume_role(
            RoleArn=assume_iam_role, RoleSessionName='Airflow_Risk')

        credentials = remote_aws_assumed_role['Credentials']
        return credentials

    def get_secret(self, secret_name):
        # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
        # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        # We rethrow the exception by default.

        if self.client is None:
            self._init_client()

        try:
            get_secret_value_response = self.client.get_secret_value(
                SecretId=secret_name
            )
        except ClientError as e:
            print(f'Exception attempting to retrieve {secret_name}')
            raise e

        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = json.loads(
                get_secret_value_response['SecretString'], strict=False)
            if secret.get('remote_secret', None):
                remote_credentials = secret['remote_credentials']
                remote_aws_iam_role = SecretsManager().get_secret(
                    remote_credentials)['iam_role']

                remote_aws_iam_temporary_credentials = self.get_temporary_access_credentials_from_assume_role(
                    assume_iam_role=remote_aws_iam_role)
                remote_secrets_manager = SecretsManager(
                    aws_access_key_id=remote_aws_iam_temporary_credentials['AccessKeyId'],
                    aws_secret_access_key=remote_aws_iam_temporary_credentials['SecretAccessKey'],
                    aws_session_token=remote_aws_iam_temporary_credentials['SessionToken']
                )
                remote_secret = remote_secrets_manager.get_secret(
                    secret['remote_secret'])

                key_mapping = json.loads(secret.get('key_mapping') or "{}")
                reverse_key_mapping = dict((v, k)
                                           for k, v in key_mapping.items())

                remote_secret_remapped = {}

                for key, value in remote_secret.items():
                    if key in reverse_key_mapping.keys():
                        new_key = reverse_key_mapping[key]
                        remote_secret_remapped[new_key] = value
                    else:
                        remote_secret_remapped[key] = value

                return remote_secret_remapped

            return secret
        else:
            decoded_binary_secret = base64.b64decode(
                get_secret_value_response['SecretBinary'])
            return decoded_binary_secret

