import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3
from typing import Any, Dict

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
DEFAULT_INDICATORS_THRESHOLD = 65
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def get_ds(self) -> Dict[str, Any]:
        """Request scanned data sources.

        Args:

        Returns:
            array: array containing the names of data sources
        """

        return self._http_request(
            method='GET',
            url_suffix='/catalog/dataSources',
            params={
            }
        )

    def get_scans_status(self) -> Dict[str, Any]:
        """Get full list of scans in the system and their status.

        Args:

        Returns:
            array: array containing the names of data sources
        """

        return self._http_request(
            method='GET',
            url_suffix='/scans/status',
            params={
            }
        )

    # TODO: should I include the format feild (cuz i only think it works with json)
    def get_objects_from_catalog(self, skip, limit, filt, sort, ignoreLimit, sample,
                                 requireTotalCount, getColumnOrFieldOccurrencesCounterFlag,
                                 getNumIdentitiesFlag, objectsCountTimeoutSec) -> Dict[str, Any]:
        """Fetches objects from the discovery catalog with the given filter string (can be taken from search bar in bigid).

        Args:
            skip (number): Bypass the first of results. If skip = 5 and limit = 100, the api will return the last 95 objects.
            limit (number): Limit the number of results to return. The response limit for the json response is 10,000 rows.
            filter (str): filter that will be used to select results from catalog
            sort (str): Sort the results by ID in ascending or descending order.
                The array is first converted into a string and then sorted in the specified order.
            ignoreLimit (boolean): default: false
            sample (number): indicate the number of files to randomly sample. default: null
            requireTotalCount (str): If true, returns the total number of results. default: false
            getColumnOrFieldOccurrencesCounterFlag (str): default: false
            getNumIdentitiesFlag: default: false
            objectsCountTimeoutSec: (str):

        Returns:
            dict: dict containing the information of all objects returned by search
        """
        return self._http_request(
            method='GET',
            url_suffix='/data-catalog/',
            params={
                'skip': skip,
                'limit': limit,
                'filter': filt,
                'sort': sort,
                'ignoreLimit': ignoreLimit,
                'sample': sample,
                'requireTotalCount': requireTotalCount,
                'getColumnOrFieldOccurrencesCounterFlag': getColumnOrFieldOccurrencesCounterFlag,
                'getNumIdentitiesFlag': getNumIdentitiesFlag,
                'objectsCountTimeoutSec': objectsCountTimeoutSec
            }
        )

    def get_ds_connections(self, skip, limit, requireTotalCount, sort, filt) -> Dict[str, Any]:
        """Retrieve one or more data source connections.

        Args:
            skip (number): Bypass the first of results. If skip = 5 and limit = 100, the api will return the last 95 objects.
            limit (number): Limit the number of results to return. The response limit for the json response is 10,000 rows.
            filter (str): filter that will be used to select results from catalog
            sort (str): Sort the results by ID in ascending or descending order.
                The array is first converted into a string and then sorted in the specified order.
            sample (number): indicate the number of files to randomly sample. default: null
            requireTotalCount (str): If true, returns the total number of results. default: false

        Returns:
            dict: dict containing the data sources and information about them (may vary on data source type, see bigid docs)
        """
        return self._http_request(
            method='GET',
            url_suffix='/ds-connections',
            params={
                'skip': skip,
                'limit': limit,
                'filter': filt,
                'sort': sort,
                'requireTotalCount': requireTotalCount,
            }
        )

    def get_session_token(self) -> Dict[str, Any]:
        """exchanges the user_token for a session_token that can be used in further api calls

        Args:

        Returns:
            dict: dict containing the session token with key 'systemToken'
        """
        return self._http_request(
            method='GET',
            url_suffix='/refresh-access-token',
            params={
            }
        )

    def initiate_scan(self, scanType, scanProfileName, scanOrigin, pii_record_id,
                      with_investigation_window, record, type_of) -> Dict[str, Any]:
        """Initiate a scan by scan profile.

        Args:
            scanType (str): Options- lineageScan, dataInMotion, metadataScan, dsScan.
            scanProfileName (str): Thr profile name to use.
            scanOrigin (str|null):
            pii_record_id (str): For investigation scan only.
            with_investigation_window (boolean):
            record (str|null): For investigation scan only.
            type (str): For investigation scan only.

        Returns:
            dict: dict containing the information of all objects returned by search
        """
        return self._http_request(
            method='POST',
            url_suffix='/scans',
            json_data={
                'scanType': scanType,
                'scanProfileName': scanProfileName,
                'scanOrigin': scanOrigin,
                'pii_record_id': pii_record_id,
                'with_investigation_window': with_investigation_window,
                'record': record,
                'type': type_of
            }
        )

    def run_ds_scan(self, connectionName, isSampleScan, scanType, autoAssumeScanType) -> Dict[str, Any]:
        """Run a scan on a data source.

        Args:
            connectionName (str): data source name
            isSampleScan (boolean): Is sample scan?
            scanType (str):scan type; one of the known BigID scan types
            autoAssumeScanType (boolean): Should server assume the scan type automatically?
              if set as true, scan type of "s3" will be HyperScan and "kinesis" will be scanned with Data In Motion scan.


        Returns:
            dict: dict containing the information of all objects returned by search
        """
        return self._http_request(
            method='POST',
            url_suffix=f'/ds-connections/{connectionName}/scan',
            params={
                'isSampleScan': isSampleScan,
                'scanType': scanType,
                'autoAssumeScanType': autoAssumeScanType,
            }
        )


''' COMMAND FUNCTIONS '''


def get_ds_command(client: Client) -> CommandResults:
    """
    get-data-sources command: Returns array of data source names in bigid instance.

    Args:
        client (Client): HelloWorld client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['name']`` is used as input name.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``.
    """
    result = client.get_ds()
    readable_output = f'## {result}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='BigId.Datasources',
        outputs_key_field='',
        outputs=result
    )


def get_scans_status_command(client: Client) -> CommandResults:
    """
    get-scans-status command: Get full list of scans in the system and their status.

    Args:
        client (Client): Bigid client to use.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, List of scans and their status.
    """
    result = client.get_scans_status()

    readable_output = f'## {result}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='BigId.ScansStatus',
        outputs_key_field='',
        outputs=result
    )


def get_objects_from_catalog_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    get-objects-from-catalog command: Gets a list of objects from the catalog and their metadata.

    Args:
        client (Client): BigId client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``.
    """
    # TODO: Do we have to cast certain values like skip and limit to int ect
    skip = args.get('skip')

    limit = args.get('limit')

    filt = args.get('filter')

    sort = args.get('sort')

    ignoreLimit = args.get('ignoreLimit')

    sample = args.get('sample')

    requireTotalCount = args.get('requireTotalCount')

    getColumnOrFieldOccurrencesCounterFlag = args.get('getColumnOrFieldOccurrencesCounterFlag')

    getNumIdentitiesFlag = args.get('getNumIdentitiesFlag')

    objectsCountTimeoutSec = args.get('objectsCountTimeoutSec')

    result = client.get_objects_from_catalog(
        skip,
        limit,
        filt,
        sort,
        ignoreLimit,
        sample,
        requireTotalCount,
        getColumnOrFieldOccurrencesCounterFlag,
        getNumIdentitiesFlag,
        objectsCountTimeoutSec
    )

    readable_output = f'## {result}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='BigId.FilteredObjects',
        outputs_key_field='results.fullyQualifiedName',
        outputs=result
    )


def get_ds_connections_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    get-ds-connections command: Gets datasource connections in BigId instance as well as their metadata

    Args:
        client (Client): BigId client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``.
    """
    # TODO: Do we have to cast certain values like skip and limit to int ect
    skip = args.get('skip')

    limit = args.get('limit')

    filt = args.get('filter')

    sort = args.get('sort')

    requireTotalCount = args.get('requireTotalCount')

    result = client.get_ds_connections(
        skip,
        limit,
        requireTotalCount,
        sort,
        filt
    )

    readable_output = f'## {result}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='BigId.DatasourceConnections',
        outputs_key_field='data.ds_connections.name',
        outputs=result
    )


def initiate_scan_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    initiate-scan command: initiates a scan in bigid given the following parameters in args

    Args:
        client (Client): BigId client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``
    """
    scanType = args.get('scanType')
    scanProfileName = args.get('scanProfileName')
    scanOrigin = args.get('scanOrigin')
    pii_record_id = args.get('pii_record_id')
    with_investigation_window = args.get('with_investigation_window')
    record = args.get('record')
    type_of = args.get('type')

    result = client.initiate_scan(
        scanType,
        scanProfileName,
        scanOrigin,
        pii_record_id,
        with_investigation_window,
        record,
        type_of
    )

    readable_output = f'## {result}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='BigId.InitiatedScan',
        outputs_key_field='_id',
        outputs=result
    )


def run_ds_scan_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    run-ds-scan command: initiates a ds scan in bigid given the following parameters in args

    Args:
        client (Client): BigId client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``
    """
    connectionName = args.get('connectionName')
    isSampleScan = args.get('isSampleScan')
    scanType = args.get('scanType')
    autoAssumeScanType = args.get('autoAssumeScanType')

    result = client.run_ds_scan(
        connectionName,
        isSampleScan,
        scanType,
        autoAssumeScanType
    )

    readable_output = f'## {result}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='BigId.DatasourceScanResults',
        outputs_key_field='_id',
        outputs=result
    )


def test_module(client: Client):
    try:
        client.get_ds()
    except DemistoException as e:
        if 'Authorization' in str(e):
            return 'Authorization Error: make sure API Token is correctly set'
        else:
            raise e
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('apikey', {}).get('password')

    # get the service API url
    base_url = urljoin(params.get('url'), '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    # Integration that implements reputation commands (e.g. url, ip, domain,..., etc) must have
    # a reliability score of the source providing the intelligence data.
    # reliability = params.get('integrationReliability', DBotScoreReliability.C)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(f'Command being called is {command}')
    try:
        auth_headers = {
            'Authorization': f'{api_key}'
        }
        # create a session client that makes a GET /refresh-access-token call to provide a session token
        session_client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=auth_headers,
            proxy=proxy)

        session_token_dict = session_client.get_session_token()

        headers = {
            'Authorization': f'{session_token_dict.get("systemToken")}'
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'get-data-sources':
            return_results(get_ds_command(client))
        elif command == 'get-objects-from-catalog':
            return_results(get_objects_from_catalog_command(client, args))
        elif command == 'get-ds-connections':
            return_results(get_ds_connections_command(client, args))
        elif command == 'initiate-scan':
            return_results(initiate_scan_command(client, args))
        elif command == 'run-ds-scan':
            return_results(run_ds_scan_command(client, args))
        elif command == 'get-scans-status':
            return_results(get_scans_status_command(client))

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command. given api key is {api_key}\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
