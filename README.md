## ontapsh REST API
ontapsh is a Python script that emulate an ONTAP shell using the most common used commands.
The aim of this script is to used ONTAP REST API from a single shell. The [documentation](https://10.65.176.31/docs/api/) is available in cot-3-demofr.

**WARNING** Never used this script on production system the aim is only for LAB and Demo

The script need to be used with **python 3**

The folowing python modules must be installed (windows):
```
pip install ssl
pip install json
pip install OpenSSL 
pip insatll urllib3
pip install requests
```
The folowing python modules must be installed (Linux):
```
python3 -m pip install pyopenssl
python3 -m pip insatll urllib3
python3 -m pip install requests
```


## ontaps sh manual
### how to use the script

Task|Command |Description|status
----|--------|-----------|------
Start ONTAP Shell Wind | **C:\python ontapsh.py** | Need python 3 | ok 
Start ONTAP Shell Linux | **# pyhton3 ontapsh.py** | Need python 3 | ok 
Run a given command | > *command_name args* | The prompt is waiting for command | ok
Display help | > **help** | - |ok
Set debug mode  | > **set debug** | Ontapsh will Display REST contents API and more information | ok
Exit debug mode | > **set nodebug**  | - | ok
Connect to ONTAP | > **set hostname** *ontap_admin_hostname or ip* <br> > **set login** <br> | set or change the ontap hostname and login/password | ok
Show ONTAP connection parameters | > **show** | - | ok
Display SVM list | > **vserver show -summary** | - | ok
Display SVM parameters | > **vserver show -vserver** *vserver_name or  filter* | - | ok 
Display Aggr list | > **aggr show -summary** | - | ok
Display Aggr parameters | > **aggr show -aggr** *aggr_name or filter* | - | ok
Display Volume list | > **volume show -summary [-vserver** *vserver_name or filter*  **] [-volume** *volume_name or filter* **]** | - | ok
Display Volume parameters | > **volume show  [-vserver** *vserver_name or filter*  **] [-volume** *volume_name or filter* **]** | - | ok
Create volume | > **volume create -vserver** *vserver_name* **-volume** *volume_name* **-size** *volume_size* **-aggregate** *aggr_name* **-language** *langue* **-type** *volume_type* | - | ok
Change volume state | > **volume [online or offline] [-vserver** *vserver_name or filter*  **] [-volume** *volume_name or filter* **]** | - |  ok
Delete volume | > **volume delete [-vserver** *vserver_name or filter*  **] [-volume** *volume_name or filter* **]** | - | ok
Display snapshot list | > **snpashot show -summary [-vserver** *vserver_name or filter*  **] [-volume** *volume_name or filter* **] **[-snapshot** *snapshot_name or filter* **]** | - | ok
Display snapshot parameters | > **snapshot show  [-vserver** *vserver_name or filter*  **] [-volume** *volume_name or filter* **]** | - | ok
Create snapshot | > **snapshot create -vserver** *vserver_name* **-volume** *volume_name* **-snapname** *snapshot_name* | - | ok
Delete snapshot | > **snapshot delete -summary [-vserver** *vserver_name or filter*  **] [-volume** *volume_name or filter* **]** **[-snapshot** *snapshot_name or filter* **]** | - | ok
Next qtree... | ... | ... | ...

### Status Flag:
**OK** : Terminate <br>
**UC** : Under construction <br>
**TDL** : In the todo list <br>


# Example how to use ONTAP CLI
```
PS C:\Users\blanchet\ONTAP_REST> python ontapsh.py
>  show
hostname:cot-3-demofr
user:admin
password:netapp123
>  vserver show -summary-vserver TEST
SVM : TEST
>  vserver show -summary-vserver T*
SVM : TEST
>  vserver show -summary-vserver T*|t*
SVM : TEST
SVM : test_dr
>  aggr show -summary
Aggregate : data1
Aggregate : data_ssd
>  volume show -summary-vserver TEST -volume *API1|*API2
volume: VolTestAPI2
volume: VolTestAPI1
>  volume show -vserver TEST -volume VolTestAPI2
volume VolTestAPI2 name: VolTestAPI2
volume VolTestAPI2 uuid: 805783f5-7a7c-11e9-bd63-00a0987fafe2
volume VolTestAPI2 SVM: TEST
volume VolTestAPI2 size: 20971520
volume VolTestAPI2 space used: 884736
volume VolTestAPI2 space available: 19038208

>  snapshot show -summary-vserver TEST -volume VolTestAPI2
volume: VolTestAPI2 snap : weekly.2019-05-26_0015
volume: VolTestAPI2 snap : daily.2019-05-28_0010
volume: VolTestAPI2 snap : daily.2019-05-29_0010
volume: VolTestAPI2 snap : hourly.2019-05-29_0905
volume: VolTestAPI2 snap : hourly.2019-05-29_1005
volume: VolTestAPI2 snap : hourly.2019-05-29_1105
volume: VolTestAPI2 snap : hourly.2019-05-29_1205
volume: VolTestAPI2 snap : hourly.2019-05-29_1305
volume: VolTestAPI2 snap : hourly.2019-05-29_1405

>  help
help:
show : Display current seting
set debug :  Enable debug mode and dislay REST API
set nodebug : Eisable debug mode
set login: Enter new login and password
set hostname <hostname> : Set ONTAP hostname or ip to connect
set ssl : Enable Secure connection
set nossl : Disable Secure connection

vol  show    [-volume  <name> ] [-vserver <name>] [-summary]
vol create -volume  <name> -vserver <name> -aggregate <name> [-size <size>]
vol delete -volume  <name> -vserver <name> [-aggregate <name>]
snap show    [-volume  <name> ] [-vserver <name>] [-snap <name>] [-summary]
snap create  -volume  <name>  -vserver <name> -snap <name>
aggr show    [-volume  <name>] [-node <name>] [-summary]
svm  show    [-vserver <name>] -[summary]

history [clear]
!<index>: run history command

```

# Example how to show REST API Request and REST API Response:
```
PS C:\Users\blanchet\ONTAP_REST> python ontapsh.py
>  volume show -volume VolTestAPI2
volume VolTestAPI2 name: VolTestAPI2
volume VolTestAPI2 uuid: 805783f5-7a7c-11e9-bd63-00a0987fafe2
volume VolTestAPI2 SVM: TEST
volume VolTestAPI2 size: 20971520
volume VolTestAPI2 space used: 884736
volume VolTestAPI2 space available: 19038208


>  set debug
DEBUG: >  volume show -volume VolTestAPI2
DEBUG: [filters: name=VolTestAPI2&svm.name=*&]
DEBUG: [https://cot-3-demofr/api/storage/volumes?name=VolTestAPI2&svm.name=*&return_records=true&return_timeout=15]
DEBUG: [status_code: 200]
DEBUG: [content-Type: application/hal+json]
DEBUG: [url: https://cot-3-demofr/api/storage/volumes?name=VolTestAPI2&svm.name=*&return_records=true&return_timeout=15]
DEBUG: [{
  "records": [
    {
      "uuid": "805783f5-7a7c-11e9-bd63-00a0987fafe2",
      "name": "VolTestAPI2",
      "svm": {
        "name": "TEST"
      },
      "_links": {
        "self": {
          "href": "/api/storage/volumes/805783f5-7a7c-11e9-bd63-00a0987fafe2"
        }
      }
    }
  ],
  "num_records": 1,
  "_links": {
    "self": {
      "href": "/api/storage/volumes?name=VolTestAPI2&svm.name=*&return_records=true&return_timeout=15"
    }
  }
}]
DEBUG: [REST Number of properties: [3]]
DEBUG: [{"records": [{"uuid": "805783f5-7a7c-11e9-bd63-00a0987fafe2", "name": "VolTestAPI2", "svm": {"name": "TEST"}, "_links": {"self": {"href": "/api/storage/volumes/805783f5-7a7c-11e9-bd63-00a0987fafe2"}}}], "num_records": 1, "_links": {"self": {"href": "/api/storage/volumes?name=VolTestAPI2&svm.name=*&return_records=true&return_timeout=15"}}}]
DEBUG: [records]
DEBUG: [[{'uuid': '805783f5-7a7c-11e9-bd63-00a0987fafe2', 'name': 'VolTestAPI2', 'svm': {'name': 'TEST'}, '_links': {'self': {'href': '/api/storage/volumes/805783f5-7a7c-11e9-bd63-00a0987fafe2'}}}]]
DEBUG: [{'uuid': '805783f5-7a7c-11e9-bd63-00a0987fafe2', 'name': 'VolTestAPI2', 'svm': {'name': 'TEST'}, '_links': {'self': {'href': '/api/storage/volumes/805783f5-7a7c-11e9-bd63-00a0987fafe2'}}}]
DEBUG: [Volume Name: VolTestAPI2]
DEBUG: [Volume uuid: 805783f5-7a7c-11e9-bd63-00a0987fafe2]
DEBUG: [num_records]
DEBUG: [_links]
DEBUG: [{'VolTestAPI2': '805783f5-7a7c-11e9-bd63-00a0987fafe2'}]
DEBUG: [https://cot-3-demofr/api/storage/volumes/805783f5-7a7c-11e9-bd63-00a0987fafe2?return_records=true&return_timeout=15]
DEBUG: [status_code: 200]
DEBUG: [content-Type: application/hal+json]
DEBUG: [url: https://cot-3-demofr/api/storage/volumes/805783f5-7a7c-11e9-bd63-00a0987fafe2?return_records=true&return_timeout=15]
DEBUG: [{
  "uuid": "805783f5-7a7c-11e9-bd63-00a0987fafe2",
  "comment": "string",
  "create_time": "2019-05-19T23:24:36+02:00",
  "language": "c.utf_8",
  "name": "VolTestAPI2",
  "size": 20971520,
  "state": "online",
  "style": "flexvol",
  "tiering": {
    "policy": "none"
  },
  "type": "rw",
  "aggregates": [
    {
      "name": "data1",
      "uuid": "09732abe-91cd-44fc-a3b1-7be87724f248"
    }
  ],
  "clone": {
    "is_flexclone": false
  },
  "nas": {
    "export_policy": {
      "name": "default"
    }
  },
  "snapshot_policy": {
    "name": "default"
  },
  "svm": {
    "name": "TEST",
    "uuid": "049b086a-dfbe-11e5-b9a7-00a0987fafe8"
  },
  "space": {
    "size": 20971520,
    "available": 19038208,
    "used": 884736
  },
  "metric": {
    "timestamp": "2019-05-29T12:41:45Z",
    "duration": "PT15S",
    "status": "ok",
    "latency": {
      "other": 0,
      "total": 0,
      "read": 0,
      "write": 0
    },
    "iops": {
      "read": 0,
      "write": 0,
      "other": 0,
      "total": 0
    },
    "throughput": {
      "read": 0,
      "write": 0,
      "other": 0,
      "total": 0
    }
  },
  "_links": {
    "self": {
      "href": "/api/storage/volumes/805783f5-7a7c-11e9-bd63-00a0987fafe2"
    }
  }
}]
DEBUG: [REST Number of properties: [18]]
DEBUG: [{"uuid": "805783f5-7a7c-11e9-bd63-00a0987fafe2", "comment": "string", "create_time": "2019-05-19T23:24:36+02:00", "language": "c.utf_8", "name": "VolTestAPI2", "size": 20971520, "state": "online", "style": "flexvol", "tiering": {"policy": "none"}, "type": "rw", "aggregates": [{"name": "data1", "uuid": "09732abe-91cd-44fc-a3b1-7be87724f248"}], "clone": {"is_flexclone": false}, "nas": {"export_policy": {"name": "default"}}, "snapshot_policy": {"name": "default"}, "svm": {"name": "TEST", "uuid": "049b086a-dfbe-11e5-b9a7-00a0987fafe8"}, "space": {"size": 20971520, "available": 19038208, "used": 884736}, "metric": {"timestamp": "2019-05-29T12:41:45Z", "duration": "PT15S", "status": "ok", "latency": {"other": 0, "total": 0, "read": 0, "write": 0}, "iops": {"read": 0, "write": 0, "other": 0, "total": 0}, "throughput": {"read": 0, "write": 0, "other": 0, "total": 0}}, "_links": {"self":
{"href": "/api/storage/volumes/805783f5-7a7c-11e9-bd63-00a0987fafe2"}}}]
DEBUG: [uuid]
DEBUG: [uuid: 805783f5-7a7c-11e9-bd63-00a0987fafe2]
DEBUG: [comment]
DEBUG: [comment: string]
DEBUG: [create_time]
DEBUG: [create_time: 2019-05-19T23:24:36+02:00]
DEBUG: [language]
DEBUG: [language: c.utf_8]
DEBUG: [name]
DEBUG: [name: VolTestAPI2]
DEBUG: [size]
DEBUG: [size: 20971520]
DEBUG: [state]
DEBUG: [state: online]
DEBUG: [style]
DEBUG: [style: flexvol]
DEBUG: [tiering]
DEBUG: [{'policy': 'none'}]
DEBUG: [tiering_policy none]
DEBUG: [type]
DEBUG: [aggregates]
DEBUG: [[{'name': 'data1', 'uuid': '09732abe-91cd-44fc-a3b1-7be87724f248'}]]
DEBUG: [aggregates data1 ]
DEBUG: [clone]
DEBUG: [nas]
DEBUG: [snapshot_policy]
DEBUG: [svm]
DEBUG: [{'name': 'TEST', 'uuid': '049b086a-dfbe-11e5-b9a7-00a0987fafe8'}]
DEBUG: [svm TEST]
DEBUG: [space]
DEBUG: [{'size': 20971520, 'available': 19038208, 'used': 884736}]
DEBUG: [space_size 20971520 ]
DEBUG: [space_used 884736 ]
DEBUG: [space_available 19038208 ]
DEBUG: [metric]
DEBUG: [_links]
DEBUG: [<built-in method get of dict object at 0x03DE7750>]
volume VolTestAPI2 name: VolTestAPI2
volume VolTestAPI2 uuid: 805783f5-7a7c-11e9-bd63-00a0987fafe2
volume VolTestAPI2 SVM: TEST
volume VolTestAPI2 size: 20971520
volume VolTestAPI2 space used: 884736
volume VolTestAPI2 space available: 19038208

DEBUG: >  set nodebug
>
```
