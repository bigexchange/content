import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
import json


def merge_policies():
    args = demisto.args()
    first = json.loads(args.get("firstPolicy"))
    second = json.loads(args.get("secondPolicy"))

    if second:
        firstStatements = first["Statement"]
        secondStatements = second["Statement"]

        for individualStatement in secondStatements:
            firstStatements.append(individualStatement)

        first['Statement'] = firstStatements

    result = {"json": json.dumps(first)}

    return CommandResults(
        outputs_prefix='MergeS3BucketPolicy',
        outputs_key_field='',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(merge_policies())
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute MergeS3BucketPolicy. Error: {str(ex)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
