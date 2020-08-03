# What is FindMyKey?

FindMyKey is a very simple tool, which aims to help identify deviations from normal behavior of an AWS user or an Aws Access key.
It's been thought to simplifie initial investigations, when other market tools are in no place at the moment.
It checks the percentage of IPs used, Event Names, and access keys.
You can use it both hunting by users or keys.

The tool is in a very initial stage, but I intend to add more features to it as I receive feedbacks.
![](https://github.com/Siedlarczyk/FindMyKey/blob/Dev/output_findmykey.png)

![](https://github.com/Siedlarczyk/FindMyKey/blob/Dev/output_findmykey.png)

## What you'll need

- Python3
- Termcolor
- Your AccessKeyId and secret configured (too lazy to code input for the keys)
- Permissions to hit CloudTrail LookupEvents (AWSCloudTrailReadOnlyAccess policy for example)

## Installation

```
git clone https://github.com/Siedlarczyk/FindMyKey.git
cd FindMyKey
pip3 install -r requirements.txt (truth be told, you're probably like to have all the libs, except for termcolor, but here it is anyway)

All set to use it!
```

## Usage

```
python3 findmykey.py [-u USERNAME] or [-k ACCESSKEYID]

  Examples:
  python3 findmykey.py -u root
  It will check for deviations for root user for the last 15 days

  python3 findmykey.py -u root -sD 2020-07-01 -eD 2020-07-15
  It will check for deviations for root user for the specified range, if you surpress -eD will check up to now

  python3 findmykey.py -k YOURACESSKEYID
  It will check for deviations on the specified key
```

## Limitations

- The tool itself hits the LookupEvents CloudTrail endpoint, which has hard limits on AWS side. Check them in the link below
  https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html
- Limitations of events 90 days old

## Future

- Multi-User
- Interact with s3 both for output and log consume
- Adopt to Lambda for periodical autonomous check

## Feedbacks

Please share your issues, ideas and improvements. I hope this somehow helps somebody.
