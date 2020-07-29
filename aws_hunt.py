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

    print("Username " + username + '\n')

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
    #split de listas
    sourceIPListSplit, eventNameListSplit = splitterList(lst_def)

    #counting das listas
    sourceIPListSplitPercent = counting(sourceIPListSplit)
    eventNameSplitPercent = counting(eventNameListSplit)

    print(eventNameSplitPercent)
    print("Access Key ID" + username + '\n')

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

def cliParser():
    parser = argparse.ArgumentParser(description = "Program to look for unlikely usage of keys or users, calculating the percentage of services, IPs, etc")
    parser.add_argument('-u', action='store',dest ='username',
                        default = 'root', required = False,
                        help = 'Enter the username, by default it uses root')
    parser.add_argument('-k', action='store',dest ='accesskeyId',
                        default = '', required = False,
                        help = 'Enter the AccessKeyId')
    parser.add_argument('-sD', action='store',dest ='startDate',
                        default = (datetime.datetime.now() - datetime.timedelta(15)), required = False,
                        help = 'Enter the start date, by default it checks for last 15 days')
    parser.add_argument('-eD', action='store',dest ='endDate',
                        default = (datetime.datetime.now()), required = False,
                        help = 'Enter the end date, by default up to now')
    parser.add_argument('-r', action='store',dest ='region',
                        default = ('us-east-1'), required = False,
                        help = 'Enter the region, by default it checks for us-east-1')
    return parser



parser = cliParser()
args = parser.parse_args()
start = args.startDate
if args.username is not None:
        atribute = 'Username'
        value = args.username


handle = boto3.client('cloudtrail')
response = handle.lookup_events(
        LookupAttributes=[
        {
        'AttributeKey': atribute,
        'AttributeValue': value
        }],
        StartTime=start,
        EndTime=datetime.datetime.now())

lst = response['Events']
lst_def = []
for dic in lst:
    event = ''
    ct_json = json.loads(dic['CloudTrailEvent'])
    sourceIP = ct_json['sourceIPAddress']

    event = dict(sourceIp=ct_json['sourceIPAddress'],
                 username=dic['Username'],
                 EventName=dic['EventName'],
                 AccessKeyId=dic['AccessKeyId'],
                 EventId=dic['EventId'])
    lst_def.append(event)

summaryUser(lst_def,value)
