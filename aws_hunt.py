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
    percent_list = []
    for i in counter:
        value = (counter[i] / len(list) * 100.0)
        ##Adiconar IF para método de scan
        if value :
            valueStr = str(i) + ' ' + str((counter[i] / len(list) * 100.0))
            percent_list.append(valueStr)
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
def summaryUser (lst_def):
    #split de listas
    sourceIPListSplit, usernameListSplit,accessKeyIDListSplit,eventNameListSplit = splitterList(lst_def)

    #counting das listas
    sourceIPListSplitPercent = counting(sourceIPListSplit)
    usernameListSplitPercent = counting(usernameListSplit)
    AccessKeyIDListSplitPercent = counting(accessKeyIDListSplit)
    eventNameSplitPercent = counting(eventNameListSplit)
    ####PARSEAR PARA FORMATO FINAL###

    print (sourceIPListSplitPercent)
    print (AccessKeyIDListSplitPercent)
    print (eventNameSplitPercent)


def cliParser():
    parser = argparse.ArgumentParser(description = "Program to look for unlikely usage of keys or users")
    parser.add_argument('-u', action='store',dest ='username',
                        default = 'root', required = False,
                        help = 'Enter the username, by default it uses root')
    parser.add_argument('-k', action='store',dest ='accesskeyId',
                        default = '', required = False,
                        help = 'Enter the AccessKeyId')
    parser.add_argument('-d', action='store',dest ='date',
                        default = (datetime.datetime.now() - datetime.timedelta(15)), required = False,
                        help = 'Enter the date, by default it checks for last 15 days')
    return parser

parser = cliParser()
args = parser.parse_args()
start = args.date
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

summaryUser(lst_def)
