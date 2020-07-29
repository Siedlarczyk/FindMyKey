# What is FindMyKey?

FindMyKey is a very simple tool, which aims to help identify deviations from normal behavior of an AWS user or an Aws Access key.
It's been though to simplifie initial investigations, when other market tools are in no place at the moment.
It checks the percentage of IPs used, Event Names, and access keys.
You can use it both huntig by users or keys.

The tool is very embrionary, but I intend to add more features to it as I receive feedbacks.

## What you'll nedd

- Python3(tested on version 1.11.6)
- Termocolor

## Installation

```
git clone 
cd FindMyKey

All set to use it!
```

## Usage

```
./python3 findmykey.py [-u USERNAME] [-k ACCESSKEYID]
  -p PID
    Specify the username
  -k ACCESSKEYID
    Specify the Keys
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
