#This tool has the idea to retrieve logs for a specific key, ip or user and then populate with might be deviations from normal behavior use
import boto3
import json
import argparse
import datetime
from collections import Counter

#counter
def counting (list):
    list = list
    counter = Counter(list)
    percent_list =[]
    for element in counter:
        value = (counter[element] / len(list) * 100.0)
        ##Adiconar IF para método de scan
        if value :
            valueDict = dict(value=value,
                            element= element)
            percent_list.append(valueDict)
    return percent_list

#funções para separar as listas por itens de cálculo
def splitterList(lst_def):
    list_def = lst_def
    sourceIPList = []
    usernameList = []
    accessKeyIdList = []
    eventNameList = []
    for dic in list_def:
        sourceIPList.append(dic['sourceIp'])
    for dic in list_def:
        usernameList.append(dic['username'])
    for dic in list_def:
        accessKeyIdList.append(dic['AccessKeyId'])
    for dic in list_def:
        eventNameList.append(dic['EventName'])
    return sourceIPList,usernameList,accessKeyIdList,eventNameList

#função para sumarizar o uso do usuário
def summaryUser (lst_def, username):
    username = username
    #split de listas
    sourceIPListSplit, usernameListSplit,accessKeyIDListSplit,eventNameListSplit = splitterList(lst_def)

    #counting das listas
    sourceIPListSplitPercent = counting(sourceIPListSplit)
    usernameListSplitPercent = counting(usernameListSplit)
    AccessKeyIDListSplitPercent = counting(accessKeyIDListSplit)
    eventNameSplitPercent = counting(eventNameListSplit)

    print("Username {} \n".format(username))

    #printing ips
    for ip in sourceIPListSplitPercent:
        element = ip['element']
        value = str(ip['value'])
        print('IP {} {}%'.format(element,value))

    #printing keys
    for key in AccessKeyIDListSplitPercent:
        element = key['element']
        value = str(key['value'])
        print('Key {} {}%'.format(element,value))

    #printing events
    for event in eventNameSplitPercent:
        element = event['element']
        value = str(event['value'])
        print('Event {} {}%'.format(element,value))

def summaryKey (lst_def,key):
    key = key
    print (key)
    #split de listas
    sourceIPListSplit, usernameListSplit,accessKeyIDListSplit,eventNameListSplit = splitterList(lst_def)

    #counting das listas
    sourceIPListSplitPercent = counting(sourceIPListSplit)
    eventNameSplitPercent = counting(eventNameListSplit)

    print("Access Key Id {} \n".format(key))

    #printing ips
    for ip in sourceIPListSplitPercent:
        element = ip['element']
        value = str(ip['value'])
        print('IP {} {}%'.format(element,value))

    #printing events
    for event in eventNameSplitPercent:
        element = event['element']
        value = str(event['value'])
        print('Event {} {}%'.format(element,value))

def cliParser():
    parser = argparse.ArgumentParser(description = "Program to look for unlikely usage of keys or users, calculating the percentage of services, IPs, etc")
    parser.add_argument('-u', action='store',dest ='username',
                        required = False,
                        help = 'Enter the Username')
    parser.add_argument('-k', action='store',dest ='accesskeyId',
                         required = False,
                        help = 'Enter the AccessKeyId')
    parser.add_argument('-sD', dest ='startDate',
                        default = (datetime.datetime.now() - datetime.timedelta(15)), required = False,
                        help = 'Enter the start date, by default it checks for last 15 days')
    parser.add_argument('-eD', action='store',dest ='endDate',
                        default = (datetime.datetime.now()), required = False,
                        help = 'Enter the end date, by default up to now')
    return parser

def ctHandler():
    handle = boto3.client('cloudtrail')
    return handle

def parsingDate(date):
    date_entry = date
    if type(date_entry) != datetime.datetime:
        year, month, day = map(int, date_entry.split('-'))
        date = datetime.datetime(year,month,day)
    else:
        date_entry=date
    return date

def getLogs(handle, attribute,value,startTime,endTime):
    handle=handle
    attribute=attribute
    value=value
    start=startTime
    end=endTime

    response = handle.lookup_events(
            LookupAttributes=[
            {
            'AttributeKey': attribute,
            'AttributeValue': value
            }],
            StartTime=start,
            EndTime=end)
    return response

def listGen(response):
    lst = response['Events']
    lst_def = []
    for element in lst:
        event = ''
        ct_json = json.loads(element['CloudTrailEvent'])
        sourceIP = ct_json['sourceIPAddress']

        event = dict(sourceIp=ct_json['sourceIPAddress'],
                     username=element['Username'],
                     EventName=element['EventName'],
                     AccessKeyId=element['AccessKeyId'],
                     EventId=element['EventId'])
        lst_def.append(event)
    return lst_def

###MAIN###
parser = cliParser()
args = parser.parse_args()
start = parsingDate(args.startDate)
end = parsingDate(args.endDate)
username = args.username

key = args.accesskeyId

if username is not None:
        attribute = 'Username'
        value = username
else:
        attribute = 'AccessKeyId'
        value = key

handle = ctHandler()
response = getLogs(handle,attribute,value,start,end)
lst_def = listGen(response)

summaryUser(lst_def,value)
