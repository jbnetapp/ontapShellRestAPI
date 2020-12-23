#################################################################################################
# Version 03
# API Rest ONTAP module jerome.blanchet@netapp.com
#################################################################################################
import ssl
import json
import OpenSSL 
import urllib3
import requests
from requests.auth import HTTPBasicAuth

#################################################################################################
# Global Parameters for ontap rest module 
#################################################################################################
DEFAULT_SSL_PORT=443
DEFAULT_API_TIMEOUT='15'
#################################################################################################
api_timeout=DEFAULT_API_TIMEOUT
secure_connect=False
Debug=False
#################################################################################################
# print debug
#################################################################################################
def print_deb (debug_var):
    if (Debug):
        print("DEBUG: [", end="") 
        print(debug_var,end="]\n")

#################################################################################################
# API-L1
# REST Protocol Function
#################################################################################################

#################################################################################################
# API-L1 rest_api_get 
#################################################################################################
def rest_api_get(hostname,user,password,rest_cmd,request_filter={}):
    rfilter=''
    for filterName in request_filter:
        rfilter = rfilter + filterName + "=" + request_filter[filterName] + "&"
    print_deb("filters: " + rfilter)
    url = "https://" + hostname + rest_cmd + "?" + rfilter + "return_records=true&return_timeout=" + api_timeout
    print_deb(url)

    try:
        if (secure_connect):
            fpem = open('cert.pem','w')
            cert = ssl.get_server_certificate((hostname, DEFAULT_SSL_PORT))
            chk_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            print_deb(chk_cert.get_issuer()) 
            print_deb(chk_cert.get_subject().get_components())
            print_deb (cert)
            fpem.write(cert)
            fpem.close()
            from requests.packages.urllib3.exceptions import SubjectAltNameWarning 
            requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)
            RestResponse = requests.get(url, auth=HTTPBasicAuth(user, password), verify='cert.pem')
        else:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            RestResponse = requests.get(url, auth=HTTPBasicAuth(user, password), verify=False)

    except BaseException as e:
        print("ERROR: HTTP connection to {0} Failed: {1}".format(hostname,e))
        return ''

    status_code=format(RestResponse.status_code)
    print_deb("status_code: {0}".format(status_code))

    if (status_code=='401'):
        print("ERROR: 401 Unauthorized HTTP")
        return ''

    print_deb("content-Type: {0}".format(RestResponse.headers['content-Type']))
    print_deb("url: {0}".format(RestResponse.request.url))
    print_deb (RestResponse.text)
    
    jData = json.loads(RestResponse.content)
    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    if(RestResponse.ok!=True):
        print("ERROR: Rest API Error: status_code {0}".format(status_code))
    return jData

#################################################################################################
# API-L1 rest_api_post
#################################################################################################
def rest_api_post(hostname,user,password,rest_cmd,api_parameters={}):
    url = "https://" + hostname + rest_cmd + "?return_records=true&return_timeout=" + api_timeout 
    headers = {'Content-type': 'application/json'}

    print_deb(url)
    print_deb(api_parameters)

    if (len (api_parameters)==0): return {} 
    print_deb(url)

    try:
        if (secure_connect):
            fpem = open('cert.pem','w')
            cert = ssl.get_server_certificate((hostname, DEFAULT_SSL_PORT))
            chk_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            print_deb(chk_cert.get_issuer())
            print_deb(chk_cert.get_subject().get_components())
            print_deb (cert)
            fpem.write(cert)
            fpem.close()
            from requests.packages.urllib3.exceptions import SubjectAltNameWarning 
            requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)
            RestResponse = requests.post(url, auth=HTTPBasicAuth(user, password), verify='cert.pem', json=api_parameters, headers=headers)
        else:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            RestResponse = requests.post(url, auth=HTTPBasicAuth(user, password), verify=False, json=api_parameters, headers=headers)

    except BaseException as e:
        print("ERROR: HTTP connection to {0} Failed: {1}".format(hostname,e))
        return '' 

    status_code=format(RestResponse.status_code)
    print_deb("status_code: {0}".format(status_code))

    if (status_code=='401'):
        print("ERROR: 401 Unauthorized HTTP")
        return '' 

    print_deb("content-Type: {0}".format(RestResponse.headers['content-Type']))
    print_deb("url: {0}".format(RestResponse.request.url))
    print_deb (RestResponse.text)

    jData = json.loads(RestResponse.content)
    print_deb("REST Number of properties: [{0}]".format(len(jData)))

    if(RestResponse.ok!=True):
        print("ERROR: Rest API Error: status_code {0}".format(status_code))

    return jData 

#################################################################################################
# API-L1 rest_api_delete
#################################################################################################
def rest_api_delete(hostname,user,password,rest_cmd,request_filter={}):
    url = "https://" + hostname + rest_cmd + "?return_records=true&return_timeout=" + api_timeout 
    print_deb(url)

    try:
        if (secure_connect):
            fpem = open('cert.pem','w')
            cert = ssl.get_server_certificate((hostname, DEFAULT_SSL_PORT))
            chk_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            print_deb(chk_cert.get_issuer())
            print_deb(chk_cert.get_subject().get_components())
            print_deb (cert)
            fpem.write(cert)
            fpem.close()
            from requests.packages.urllib3.exceptions import SubjectAltNameWarning 
            requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)
            RestResponse = requests.delete(url, auth=HTTPBasicAuth(user, password), verify='cert.pem')
        else:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            RestResponse = requests.delete(url, auth=HTTPBasicAuth(user, password), verify=False)

    except BaseException as e:
        print("ERROR: HTTP connection to {0} Failed: {1}".format(hostname,e))
        return '' 

    status_code=format(RestResponse.status_code)
    print_deb("status_code: {0}".format(status_code))

    if (status_code=='401'):
        print("ERROR: 401 Unauthorized HTTP")
        return '' 

    print_deb("content-Type: {0}".format(RestResponse.headers['content-Type']))
    print_deb("url: {0}".format(RestResponse.request.url))
    print_deb (RestResponse.text)

    jData = json.loads(RestResponse.content)
    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    if(RestResponse.ok!=True):
        print("ERROR: Rest API Error: status_code {0}".format(status_code))
    return jData

#################################################################################################
# API-L1 rest_api_patch
#################################################################################################
def rest_api_patch(hostname,user,password,rest_cmd,api_parameters={}):
    url = "https://" + hostname + rest_cmd + "?return_records=true&return_timeout=" + api_timeout 
    headers = {'Content-type': 'application/json'}

    print_deb(url)
    print_deb(api_parameters)

    if (len (api_parameters)==0): return {} 
    print_deb(url)

    try:
        if (secure_connect):
            fpem = open('cert.pem','w')
            cert = ssl.get_server_certificate((hostname, DEFAULT_SSL_PORT))
            chk_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            print_deb(chk_cert.get_issuer())
            print_deb(chk_cert.get_subject().get_components())
            print_deb (cert)
            fpem.write(cert)
            fpem.close()
            from requests.packages.urllib3.exceptions import SubjectAltNameWarning 
            requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)
            RestResponse = requests.patch(url, auth=HTTPBasicAuth(user, password), verify='cert.pem', json=api_parameters, headers=headers)
        else:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            RestResponse = requests.patch(url, auth=HTTPBasicAuth(user, password), verify=False, json=api_parameters, headers=headers)

    except BaseException as e:
        print("ERROR: HTTP connection to {0} Failed: {1}".format(hostname,e))
        return '' 

    status_code=format(RestResponse.status_code)
    print_deb("status_code: {0}".format(status_code))

    if (status_code=='401'):
        print("ERROR: 401 Unauthorized HTTP")
        return '' 

    print_deb("content-Type: {0}".format(RestResponse.headers['content-Type']))
    print_deb("url: {0}".format(RestResponse.request.url))
    print_deb (RestResponse.text)

    jData = json.loads(RestResponse.content)
    print_deb("REST Number of properties: [{0}]".format(len(jData)))

    if(RestResponse.ok!=True):
        print("ERROR: Rest API Error: status_code {0}".format(status_code))

    return jData 

#################################################################################################
# API-L2-VSERVER
#################################################################################################

#################################################################################################
# API-L2 vserver_get_uuid_list Return a dictionary with the format  { svm_name : svm_uuid, ... }
# Parameters:
# <hostname> ONTAP Cluster hostname 
# <user> username 
# <password> password 
# <request_filter> = Filter to select a given svm list
# {
#   name : svm_name,
#   ...
#   ...
#   see https://<cluster_name>/docs/api for all other filter parameters 
# }
#################################################################################################
def vserver_get_uuid_list(hostname,user,password,request_filter={}):
    svm_uuid_list = {}
    message_error =""
    rest_cmd = "/api/svm/svms"
    jData = rest_api_get(hostname,user,password,rest_cmd,request_filter)
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "records"):
            print_deb (jData[jkey])
            for svm in jData[jkey]:
                print_deb (svm)
                svm_name = svm.get("name")
                svm_uuid = svm.get("uuid")
                print_deb ("SVM Name: " + svm_name)
                print_deb ("SVM uuid: " + svm_uuid)
                svm_uuid_list[svm_name]=svm_uuid
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))
    return svm_uuid_list
#################################################################################################
# API-L2 vserver_create_new  
#################################################################################################
def vserver_create_new(hostname,user,password,vserver_parameters={}):
    rest_cmd = "/api/svm/svms"
    jData = rest_api_post(hostname,user,password,rest_cmd,vserver_parameters)

    job_uuid = "" 
    message_error =""

    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "job"):
            print_deb (jData[jkey])
            job_uuid=jData[jkey].get('uuid')
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))
    print_deb("job uuid: {0}".format(job_uuid))
    return job_uuid 

#################################################################################################
# API-L2 vserver_delete_by_uuid
#################################################################################################
def vserver_delete_by_uuid(hostname,user,password,uuid):
    print_deb("Delete svm ID: {0}".format(uuid))
    request_filter={}
    rest_cmd = "/api/svm/svms/" + uuid
    jData = rest_api_delete(hostname,user,password,rest_cmd,request_filter)

    job_uuid = ""
    message_error =""

    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "job"):
            print_deb (jData[jkey])
            job_uuid=jData[jkey].get('uuid')
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))

    print_deb("job uuid: {0}".format(job_uuid))
    return job_uuid 

#################################################################################################
# API-L2-AGGR
#################################################################################################

#################################################################################################
# API-L2 aggr_get_uuid_list Return a dictionary with the format { aggr_name : aggr_uuid , ... }
# Parameters:
# <hostname> ONTAP Cluster hostname 
# <user> username 
# <password> password 
# <request_filter> = Filter to select a given volume list
# {
#   name : AggrName,
#   node.name : node_name,
#   ...
#   ...
#   see https://<cluster_name>/docs/api for all other filter parameters 
# }
#################################################################################################
def aggr_get_uuid_list(hostname,user,password,request_filter={}):
    rest_cmd = "/api/storage/aggregates"
    jData = rest_api_get(hostname,user,password,rest_cmd,request_filter)

    aggr_uuid_list = {}
    message_error =""

    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "records"):
            print_deb (jData[jkey])
            for aggr in jData[jkey]:
                print_deb (aggr)
                aggr_name = aggr.get("name")
                aggr_uuid = aggr.get("uuid")
                print_deb ("Aggr Name: " + aggr_name)
                print_deb ("Aggr uuid: " + aggr_uuid)
                aggr_uuid_list[aggr_name]=aggr_uuid
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))
    return aggr_uuid_list

#################################################################################################
# API-L2-VOLUME
#################################################################################################

#################################################################################################
# API-L2 vol_get_uuid_list Return a dictionary with the format  { volume_name : volume_uuid, ... }
# Parameters:
# <hostname> ONTAP Cluster hostname 
# <user> username 
# <password> password 
# <request_filter> = Filter to select a given volume list
# {
#   name : volumeName,
#   svm.name : svm_name,
#   ...
#   ...
#   see https://<cluster_name>/docs/api for all other filter parameters 
# }
#################################################################################################
def vol_get_uuid_list(hostname,user,password,request_filter={}):
    # Get volume uuid 
    rest_cmd = "/api/storage/volumes"
    jData = rest_api_get(hostname,user,password,rest_cmd,request_filter)

    vol_uuid_list = {}
    message_error =""

    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "records"):
            print_deb (jData[jkey])
            for vol in jData[jkey]: 
                print_deb (vol)
                vol_name = vol.get("name")
                vol_uuid = vol.get("uuid")
                print_deb ("Volume Name: " + vol_name)
                print_deb ("Volume uuid: " + vol_uuid)
                vol_uuid_list[vol_name]=vol_uuid
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))
    return vol_uuid_list

#################################################################################################
# API-L2 vol_get_parameters Return a dictionary with the format  { volume_parameters1 : value1 , ... }
# Parameters:
# <hostname> ONTAP Cluster hostname 
# <user> username 
# <password> password 
# <uuid> = uuid of the volume 
#################################################################################################
def vol_get_parameters(hostname,user,password,uuid):
    rest_cmd = "/api/storage/volumes/" + uuid
    request_filter={}
    jData = rest_api_get(hostname,user,password,rest_cmd,request_filter)

    vol_parameters = {}
    message_error =""

    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb(jkey)
        if (jkey == "uuid" or jkey == "comment" or jkey == "create_time" or jkey == 'language' or
            jkey == "size" or jkey == "name" or jkey == "state" or jkey == "style" ):
                vol_parameters[jkey]=jData[jkey]
                print_deb("{0}: {1}".format(jkey,vol_parameters[jkey]))
        elif (jkey == "aggregates"):
            print_deb (jData[jkey])
            aggr_list = ""
            for aggr in jData[jkey]:
                aggr_list = aggr_list + aggr.get("name") + " "
                vol_parameters['aggregates']=aggr_list
            print_deb ("aggregates " + vol_parameters['aggregates'])
        elif (jkey == "tiering"):
            print_deb (jData[jkey])
            tiering=jData[jkey] 
            vol_parameters['tiering_policy']=tiering.get('policy')
            print_deb ("tiering_policy " + vol_parameters['tiering_policy'])
        elif (jkey == "svm"):
            print_deb (jData[jkey])
            svm=jData[jkey] 
            vol_parameters['svm']=svm.get('name')
            print_deb ("svm " + vol_parameters['svm'])
        elif (jkey == "space"):
            print_deb (jData[jkey])
            space=jData[jkey] 
            vol_parameters['space_size']=space.get('size')
            vol_parameters['space_used']=space.get('used')
            vol_parameters['space_available']=space.get('available')
            print_deb ("space_size {0} ".format(vol_parameters['space_size']))
            print_deb ("space_used {0} ".format(vol_parameters['space_used']))
            print_deb ("space_available {0} ".format(vol_parameters['space_available']))
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))
    return vol_parameters


#################################################################################################
# API-L2 vol_patch_parameters 
#################################################################################################
def vol_patch_parameters(hostname,user,password,uuid,volume_parameters={}):
    rest_cmd = "/api/storage/volumes/" + uuid
    jData = rest_api_patch(hostname,user,password,rest_cmd,volume_parameters)

    job_uuid = "" 
    message_error =""

    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "job"):
            print_deb (jData[jkey])
            job_uuid=jData[jkey].get('uuid')
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))
    print_deb("job uuid: {0}".format(job_uuid))
    return job_uuid 

#################################################################################################
# API-L2 vol_create_new 
#################################################################################################
def vol_create_new(hostname,user,password,volume_parameters={}):
    rest_cmd = "/api/storage/volumes"
    jData = rest_api_post(hostname,user,password,rest_cmd,volume_parameters)

    job_uuid = "" 
    message_error =""

    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "job"):
            print_deb (jData[jkey])
            job_uuid=jData[jkey].get('uuid')
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))
    print_deb("job uuid: {0}".format(job_uuid))
    return job_uuid 
#################################################################################################
# API-L2 vol_delete_by_uuid
#################################################################################################
def vol_delete_by_uuid(hostname,user,password,uuid):
    print_deb("Delete volume ID: {0}".format(uuid))
    request_filter={}
    rest_cmd = "/api/storage/volumes/" + uuid
    jData = rest_api_delete(hostname,user,password,rest_cmd,request_filter)

    job_uuid = ""
    message_error =""

    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "job"):
            print_deb (jData[jkey])
            job_uuid=jData[jkey].get('uuid')
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))

    print_deb("job uuid: {0}".format(job_uuid))
    return job_uuid 

#################################################################################################
# API-L2-SNAP
#################################################################################################

#################################################################################################
# API-L2 snap_get_uuid_list Return a dictionary with the format  { snap_name : snap_uuid }
# Parameters:
# <hostname> ONTAP Cluster hostname 
# <user> username 
# <password> password 
# <vol_uuid>  volume uuid where to get snap list 
# <request_filter> = Filter to select a given volume list
# {
#   name : snapname,
#   ...
#   see https://<cluster_name>/docs/api for all other filter parameters 
# }
#################################################################################################
def snap_get_uuid_list(hostname,user,password,vol_uuid,request_filter={}):
    rest_cmd = "/api/storage/volumes/" + vol_uuid + "/snapshots"
    jData = rest_api_get(hostname,user,password,rest_cmd,request_filter)
    
    snap_uuid_list = {}
    message_error =""

    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "records"):
            print_deb (jData[jkey])
            for snap in jData[jkey]: 
                print_deb (snap)
                snap_name = snap.get("name")
                snap_uuid = snap.get("uuid")
                print_deb ("Snapshot Name: " + snap_name)
                print_deb ("Snapshot uuid: " + snap_uuid)
                snap_uuid_list[snap_name]=snap_uuid
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))
    return snap_uuid_list

#################################################################################################
# API-L2 snap_create_new 
#################################################################################################
def snap_create_new(hostname,user,password,uuid,snapshot_parameters={}):
    rest_cmd = "/api/storage/volumes/" + uuid + "/snapshots"
    jData = rest_api_post(hostname,user,password,rest_cmd,snapshot_parameters)

    job_uuid = "" 
    message_error =""

    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "job"):
            print_deb (jData[jkey])
            job_uuid=jData[jkey].get('uuid')
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))

    print_deb("job uuid: {0}".format(job_uuid))
    return job_uuid 

#################################################################################################
# API-L2 snap_delete_by_uuid: delete snapshot by uuid
#################################################################################################
def snap_delete_by_uuid(hostname,user,password,vol_uuid,snap_uuid):
    print_deb("Delete Snapshot {0} on volume {1}".format(vol_uuid,snap_uuid))
    request_filter={}
    rest_cmd = "/api/storage/volumes/" + vol_uuid + "/snapshots/" + snap_uuid
    jData = rest_api_delete(hostname,user,password,rest_cmd,request_filter)

    job_uuid = "" 
    message_error =""

    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "job"):
            print_deb (jData[jkey])
            job_uuid=jData[jkey].get('uuid')
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR:{0}".format(message_error))

    print_deb("job uuid: {0}".format(job_uuid))
    return job_uuid 


#################################################################################################
# API-L2 NETWORK 
#################################################################################################
#################################################################################################
# API-L2 network_ip_interface_get_uuid_list Return a dictionary with the format  { svm_name : svm_uuid, ... }
# Parameters:
# <hostname> ONTAP Cluster hostname 
# <user> username 
# <password> password 
# <request_filter> = Filter to select a given svm list
# {
#   name : Network_ip_interface_name
#   uuid: Network_ip_interface_uuid 
#   ...
#   see https://<cluster_name>/docs/api for all other filter parameters 
# }
#################################################################################################
def network_ip_interface_get_uuid_list(hostname,user,password,request_filter={}):
    netipif_uuid_list = {}
    message_error =""
    rest_cmd = "/api/network/ip/interfaces"
    jData = rest_api_get(hostname,user,password,rest_cmd,request_filter)
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "records"):
            print_deb (jData[jkey])
            for netipif in jData[jkey]:
                print_deb (netipif)
                netipif_name = netipif.get("name")
                netipif_uuid = netipif.get("uuid")
                print_deb ("SVM Name: " + netipif_name)
                print_deb ("SVM uuid: " + netipif_uuid)
                netipif_uuid_list[netipif_name]=netipif_uuid
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))
    return netipif_uuid_list
#################################################################################################
# API-L2 network_ip_interface_create_new 
#################################################################################################
def network_ip_interface_create_new(hostname,user,password,netipif_parameters={}):
    rest_cmd = "/api/network/ip/interfaces"
    jData = rest_api_post(hostname,user,password,rest_cmd,netipif_parameters)

    job_uuid = "" 
    message_error =""

    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "job"):
            print_deb (jData[jkey])
            job_uuid=jData[jkey].get('uuid')
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))

    print_deb("job uuid: {0}".format(job_uuid))
    return job_uuid 

#################################################################################################
# API-L2 network_ip_interface_delete_by_uuid
#################################################################################################
def network_ip_interface_delete_by_uuid(hostname,user,password,uuid):
    print_deb("Delete network ip interface: {0}".format(uuid))
    request_filter={}
    rest_cmd = "/api/network/ip/interfaces/" + uuid
    jData = rest_api_delete(hostname,user,password,rest_cmd,request_filter)

    job_uuid = ""
    message_error =""

    print_deb("REST Number of properties: [{0}]".format(len(jData)))
    dump = json.dumps(jData)
    print_deb(dump)
    for jkey in jData:
        print_deb (jkey)
        if (jkey == "job"):
            print_deb (jData[jkey])
            job_uuid=jData[jkey].get('uuid')
        elif (jkey == "error"):
            print_deb (jData[jkey])
            error=jData[jkey]
            message_error=error.get("message") 
            print("ERROR: {0}".format(message_error))

    print_deb("job uuid: {0}".format(job_uuid))
    return job_uuid 

#################################################################################################
# API-L3 VSERVER
#################################################################################################

#################################################################################################
# API-L3 vserver_print_list 
#################################################################################################
def vserver_print_list(hostname,user,password,request_filter={}):
    try:
        svm_uuid_list = vserver_get_uuid_list(hostname,user,password,request_filter)
        print_deb(svm_uuid_list)
        for svm_name in svm_uuid_list:
            uuid = svm_uuid_list[svm_name]
            print("SVM : " + svm_name  )
    except BaseException as e:
        print("ERROR: {0}".format(e))
        return ''

#################################################################################################
# API-L3 vserver_delete_list 
#################################################################################################
def vserver_delete_list(hostname,user,password,request_filter={}):
    try:
        confirm='n'
        svm_uuid_list = vserver_get_uuid_list(hostname,user,password,request_filter)
        print_deb(svm_uuid_list)
        for svm_name in svm_uuid_list:
            confirm=input('delete vserver [{0}] [y/n]? '.format(svm_name))
            if (confirm=='y'):
                svm_uuid = svm_uuid_list[svm_name]
                vserver_delete_by_uuid(hostname,user,password,svm_uuid)
    except BaseException as e:
        print("ERROR: {0}".format(e))
        return ''

#################################################################################################
# API-L3 AGGR 
#################################################################################################

#################################################################################################
# API-L3 aggr_print_list 
#################################################################################################
def aggr_print_list(hostname,user,password,request_filter={}):
    try:
        aggr_uuid_list = aggr_get_uuid_list(hostname,user,password,request_filter)
        print_deb(aggr_uuid_list)
        for aggr_name in aggr_uuid_list:
            print("Aggregate : " + aggr_name )
    except BaseException as e:
        print("ERROR: {0}".format(e))
        return ''

#################################################################################################
# API-L3 VOLUME
#################################################################################################

#################################################################################################
# API-L3 vol_print_list
#################################################################################################
def vol_print_list(hostname,user,password,request_filter={}):
    try:
        vol_uuid_list = vol_get_uuid_list(hostname,user,password,request_filter)
        print_deb(vol_uuid_list)
        if (len(vol_uuid_list)==0): 
            print ("ERROR: No volume found")
        for vol_name in vol_uuid_list:
            print("volume: " + vol_name)
    except BaseException as e:
        print("ERROR: {0}".format(e))
        return ''

#################################################################################################
# API-L3 vol_print_parameters  
#################################################################################################
def vol_print_parameters(hostname,user,password,request_filter={}):
    try:
        vol_uuid_list = vol_get_uuid_list(hostname,user,password,request_filter)
        print_deb(vol_uuid_list)
        if (len(vol_uuid_list)==0): 
            print ("ERROR: No volume found")
        for vol_name in vol_uuid_list:
            vol_uuid=vol_uuid_list[vol_name]
            vol_parameters=vol_get_parameters(hostname,user,password,vol_uuid)
            print_deb(vol_parameters)
            print("volume {0} name: {1}".format(vol_name,vol_parameters.get('name')))
            print("volume {0} uuid: {1}".format(vol_name,vol_parameters.get('uuid')))
            print("volume {0} SVM: {1}".format(vol_name,vol_parameters.get('svm')))
            print("volume {0} size: {1}".format(vol_name,vol_parameters.get('size')))
            print("volume {0} space used: {1}".format(vol_name,vol_parameters.get('space_used')))
            print("volume {0} space available: {1}".format(vol_name,vol_parameters.get('space_available')))
            print("\n")
    except BaseException as e:
        print("ERROR: {0}".format(e))
        return ''

#################################################################################################
#  API-L3 vol_delete_list 
#################################################################################################
def vol_delete_list(hostname,user,password,request_filter={}):
    try:
        confirm='n'
        vol_uuid_list = vol_get_uuid_list(hostname,user,password,request_filter)
        print_deb(vol_uuid_list)
        for vol_name in vol_uuid_list:
            confirm=input('delete volume [{0}] [y/n]? '.format(vol_name))
            if (confirm=='y'):
                vol_uuid=vol_uuid_list[vol_name]
                vol_delete_by_uuid(hostname,user,password,vol_uuid)
    except BaseException as e:
        print("ERROR: {0}".format(e))
        return ''

#################################################################################################
# API-L3 API-L3 SNAP 
#################################################################################################

#################################################################################################
# API-L3 snap_print_list
#################################################################################################
def snap_print_list(hostname,user,password,request_filter={}):
    try:
        # Create the json request for get volume request  
        vol_request_filter={}
        if ('volume.name') in request_filter :
            vol_request_filter["name"]=request_filter.get('volume.name')
        if ('svm.name') in request_filter :
            vol_request_filter["svm.name"]=request_filter.get('svm.name')
        if ('aggregates.name') in request_filter :
            vol_request_filter["aggregates.name"]=request_filter.get('aggregates.name')

        # Get volume UUID list  
        vol_uuid_list = vol_get_uuid_list(hostname,user,password,vol_request_filter)

        if (len(vol_uuid_list)==0): 
            print ("ERROR: No volume found")

        # Get snapshots names  
        for vol_name in vol_uuid_list:
            vol_uuid=vol_uuid_list[vol_name]
            print_deb('vol_name: {0}'.format(vol_name))
            print_deb('vol_uuid: {0}'.format(vol_uuid))
            snap_uuid_list = snap_get_uuid_list(hostname,user,password,vol_uuid,request_filter)
            if (len(snap_uuid_list)==0): 
                print ("No snapshot found")
            print_deb(snap_uuid_list)
            for snap_name in snap_uuid_list:
                snap_uuid=snap_uuid_list[snap_name]
                print("volume: " + vol_name + " snap : " + snap_name )

    except BaseException as e:
        print("ERROR: {0}".format(e))
        return ''

#################################################################################################
# API-L3 snap_create_on_multiple_vol:  Create new snapshot on multiple volume list 
#################################################################################################
def snap_create_on_multiple_vol(hostname,user,password,snapname,volume_filter={}):
    try:
        confirm='n'
        snapshot_parameters={}
        snapshot_parameters["name"]=snapname
        vol_uuid_list = vol_get_uuid_list(hostname,user,password,volume_filter)
        print_deb(vol_uuid_list)
        for vol_name in vol_uuid_list:
            vol_uuid=vol_uuid_list[vol_name]
            snap_create_new(hostname,user,password,vol_uuid,snapshot_parameters)
    except BaseException as e:
        print("ERROR: {0}".format(e))
        return ''

#################################################################################################
# API-L3 snap_delete_on_multiple_vol:  Create a snapshot on multiple volume list 
#################################################################################################
def snap_delete_on_multiple_vol(hostname,user,password,request_filter={}):
    try:
        confirm='n'
        # Create the json request for get volume request  
        vol_request_filter={}
        if ('volume.name') in request_filter :
            vol_request_filter["name"]=request_filter.get('volume.name')
        if ('svm.name') in request_filter :
            vol_request_filter["svm.name"]=request_filter.get('svm.name')
        if ('aggregates.name') in request_filter :
            vol_request_filter["aggregates.name"]=request_filter.get('aggregates.name')

        # Get volume UUID list  
        vol_uuid_list = vol_get_uuid_list(hostname,user,password,vol_request_filter)

        # Get snapshots names  
        for vol_name in vol_uuid_list:
            vol_uuid=vol_uuid_list[vol_name]
            print_deb('vol_name: {0}'.format(vol_name))
            print_deb('vol_uuid: {0}'.format(vol_uuid))
            snap_uuid_list = snap_get_uuid_list(hostname,user,password,vol_uuid,request_filter)
            print_deb(snap_uuid_list)
            for snap_name in snap_uuid_list:
                snap_uuid=snap_uuid_list[snap_name]
                print_deb('snap_uuid: {0}'.format(snap_uuid))
                confirm=input('delete snapshot [{0}] on volume [{1}] [y/n]? '.format(snap_name, vol_name))
                if (confirm=='y'): 
                    snap_delete_by_uuid(hostname,user,password,vol_uuid,snap_uuid)

    except BaseException as e:
        print("ERROR: {0}".format(e))
        return ''

#################################################################################################
# API-L3 NETWORK_IP 
#################################################################################################
#################################################################################################
#  API-L3 network_ip_delete_list 
#################################################################################################
def network_ip_interface_delete_list(hostname,user,password,request_filter={}):
    try:
        confirm='n'
        netipif_uuid_list = network_ip_interface_get_uuid_list(hostname,user,password,request_filter)
        print_deb(netipif_uuid_list)
        for netipif_name in netipif_uuid_list:
            confirm=input('delete network ip interface [{0}] [y/n]? '.format(netipif_name))
            if (confirm=='y'):
                netipif_uuid=netipif_uuid_list[netipif_name]
                network_ip_interface_delete_by_uuid(hostname,user,password,netipif_uuid)
    except BaseException as e:
        print("ERROR: {0}".format(e))
        return ''