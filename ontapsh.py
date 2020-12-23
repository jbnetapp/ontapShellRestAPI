#####################################################################
# ONTAP SH is a simple python script using ONTAPRest Module
# Comments jerome.blanchet@netapp.com
#####################################################################
import ontapRest 
import argparse
import getpass
import sys

RELEASE='0.2'
#####################################################################
# Local API 
#####################################################################
Debug = False

def print_vers():
      print (RELEASE)

def print_help():
      print ('                                                                                   ')
      print ('show                                  Display current setting                      ')
      print ('set debug                             Enable debug mode and dislay REST API        ')
      print ('set nodebug                           Disable debug mode                           ')
      print ('set login                             Enter new login and password                 ')
      print ('set hostname <hostname>               Set ONTAP hostname or ip to connect          ')
      print ('set timeout  <seconds>                Set api timeout in seconds                   ')
      print ('set ssl                               Enable Secure connection                     ')
      print ('set nossl                             Disable Secure connection                    ')
      print ('history [clear]                       Display command history                      ')
      print ('!<index>:                             run history command <index>                  ')
      print ('                                                                                   ')
      print ('volume    | vol                       manage ONTAP volumes    (see vol  help)      ')
      print ('snapshot  | snap                      manage ONTAP snapshots  (see snap help)      ')
      print ('aggregate | aggr                      manage ONTAP aggregates (see aggr help)      ')
      print ('vserver   | svm                       manage ONTAP SVM        (see svm help)       ')
      print ('                                                                                   ')

def print_help_vol():
      print ('                                                                                   ')
      print ('vol  show  [-vserver <name>] [-volume  <name> ] [-summary|-s]                      ')
      print ('                                                                                   ')
      print ('vol create  -vserver <name> -volume  <name> -vserver <name>                        ')
      print ('            -aggregate <name> [-size <size>]                                       ')
      print ('                                                                                   ')
      print ('vol clone   -vserver <name> -volume <name> [-parent-vserver <name> ]               ')
      print ('            -parent-volume <name> -parent-snap <name>                              ')
      print ('                                                                                   ')
      print ('vol delete -vserver <name> -volume  <name> [-aggregate <name>]                     ')
      print ('                                                                                   ')

def print_help_snap():
      print ('                                                                                   ')
      print ('snap show    [-volume  <name> ] [-vserver <name>] [-snap <name>] [-summary|-s]     ')
      print ('snap create  -volume  <name> -vserver <name> -snap <name>                          ')
      print ('snap delete  -volume  <name> -vserver <name> -snap <name>                          ')
      print ('snap show    [-volume  <name> ] [-vserver <name>] [-snap <name>] [-summary|-s]     ')
      print ('                                                                                   ')

def print_help_aggr():
      print ('                                                                                   ')
      print ('aggr show    [-volume  <name>] [-node <name>] [-summary|-s]')
      print ('                                                                                   ')

def print_help_svm():
      print ('                                                                                   ')
      print ('svm  show    [-vserver <name>] -[summary]')
      print ('                                                                                   ')

def print_syntax_error(mess):
      print ('ERROR: {0}'.format(mess))

def print_deb (debug_var):
    if (Debug):
        print("DEBUG: [", end="") 
        print(debug_var,end="]\n")

#####################################################################
# Inputs 
#####################################################################
hostname=''
user = ''
password = '' 
prompt='> '
history=[]

#####################################################################
# Main
#####################################################################
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", help="print debug informations", action="store_true")
args = parser.parse_args()
if args.debug:
      Debug = True
      ontapRest.Debug = True 
      prompt = 'DEBUG: > '

cmdline=""
history_cmline=""

if (len(hostname)==0): hostname=input('hostname : ')
if (len(user)==0): user=input('login : ')
if (len(password)==0): password=getpass.getpass('password : ')

try:
      while ( cmdline != 'quit' and cmdline != 'exit' ) :
        cli_error=False
        if (len(history_cmline)>0):
              cmdline=history_cmline
              history_cmline=""
        else: 
              cmdline=input('{0} '.format(prompt)) 
        cmdtab=cmdline.split()
        if (cmdline == 'help'):
              print_help()
        elif (cmdline == 'version'):
              print_vers()
        elif (cmdline == '' or cmdline == 'quit' or cmdline == 'exit'):
              # Do nothing
              do_nothing=True
        else:
              if (len(cmdtab)>=1): 
                    ##################################################################################################
                    # history  
                    if (cmdtab[0]=='history' or cmdtab[0]=='h'):
                          if (len(cmdtab)>=2 and cmdtab[1]=='clear'):
                              history.clear()
                          else:
                              i=0
                              for cmd in history:
                                    print("{0} {1}".format(i,cmd))
                                    i+=1 
                    elif(cmdtab[0][0]=='!'):
                        tmpstr=cmdtab[0].replace('!','')
                        if(tmpstr.isdecimal()==True):
                              cmdi=int(tmpstr)
                              hlen=len(history)
                              if (hlen > cmdi):
                                    history_cmline=history[cmdi]
                                    print(history_cmline)
                              else:
                                    cli_error=True
                                    print_syntax_error("history not found")
                        else:
                              cli_error=True
                              print_syntax_error("history syntax error see help")
                    ##################################################################################################
                    # command setup 
                    elif (cmdtab[0]=='setup' or cmdtab[0]=='set'):
                          for i in range(1,len(cmdtab)):
                                if (cmdtab[i]=='hostname'):
                                      if (len(cmdtab)>i+1) :
                                            hostname=cmdtab[i+1]
                                            cmdtab[i+1]="hostname_done"
                                elif (cmdtab[i]=='timeout'):
                                      if (len(cmdtab)>i+1) :
                                            if (cmdtab[i+1].isdecimal()==True):
                                                ontapRest.api_timeout=cmdtab[i+1]
                                            else:
                                                print_syntax_error("Error time must be in seconds")
                                            cmdtab[i+1]="timeout_done"
                                elif (cmdtab[i]=='hostname_done'):
                                      print_deb(hostname)
                                elif (cmdtab[i]=='timeout_done'):
                                      print_deb(ontapRest.api_timeout) 
                                elif (cmdtab[i]=='ssl'):
                                      ontapRest.secure_connect=True
                                elif (cmdtab[i]=='nossl'):
                                      ontapRest.secure_connect=False
                                elif (cmdtab[i]=='debug'):
                                      Debug=True
                                      ontapRest.Debug=True
                                      prompt = 'DEBUG: > '
                                elif (cmdtab[i]=='nodebug'):
                                      Debug=False
                                      ontapRest.Debug=False
                                      prompt = '> '
                                elif (cmdtab[i]=='login'): 
                                      user=input('login: ')
                                      password=getpass.getpass('password: ')
                                else:
                                      cli_error=True
                          if (cli_error==True): 
                                print_syntax_error("{0}: syntax error see help".format(cmdtab[0]))
      
                    ##################################################################################################
                    # command show
                    elif (cmdtab[0]=='show'):
                          print('hostname: ' + hostname )
                          print('user: ' + user )
                          print('SSL: {0}'.format(ontapRest.secure_connect) )
                          print('timeout: {0}'.format(ontapRest.api_timeout) )
                    ##################################################################################################
                    # command Volume | vol
                    elif (cmdtab[0]=='volume' or cmdtab[0]=='vol'):
                          # Rest volume vars 
                          cli_vol_volname=''
                          cli_vol_vserver=''
                          cli_vol_aggrname=''
                          cli_vol_parent_vol=''
                          cli_vol_parent_snap=''
                          cli_vol_parent_vserver=''
                          cli_vol_size=''
                          cli_vol_help=False
                          cli_vol_show=False
                          cli_vol_list=False
                          cli_vol_create=False
                          cli_vol_clone=False
                          cli_vol_delete=False
                          cli_vol_create=False
                          cli_ignore_arg = False 
                          for i in range(1,len(cmdtab)):
                                if (cli_ignore_arg): 
                                      cli_ignore_arg=False
                                elif (cmdtab[i]=='help'):
                                      cli_vol_help=True
                                elif (cmdtab[i]=='create'):
                                      cli_vol_create=True
                                elif (cmdtab[i]=='delete' or cmdtab[i]=='del'):
                                      cli_vol_delete=True
                                elif (cmdtab[i]=='clone'):
                                      cli_vol_clone=True
                                elif (cmdtab[i]=='show'):
                                      cli_vol_show=True
                                elif (cmdtab[i]=='-summary' or cmdtab[i]=='-sum' or cmdtab[i]=='-s'):
                                      cli_vol_list=True
                                elif (cmdtab[i]=='-volume' or cmdtab[i]=='-vol'):
                                      if (len(cmdtab)>i+1) :
                                            cli_vol_volname=cmdtab[i+1]
                                            cli_ignore_arg=True
                                elif (cmdtab[i]=='-aggregate' or cmdtab[i]=='-aggr'):
                                      if (len(cmdtab)>i+1) :
                                            cli_vol_aggrname=cmdtab[i+1]
                                            cli_ignore_arg=True
                                elif (cmdtab[i]=='-vserver'):
                                      if (len(cmdtab)>i+1) : 
                                            cli_vol_vserver=cmdtab[i+1]
                                            cli_ignore_arg=True
                                elif (cmdtab[i]=='-parent-volume' or cmdtab[i]=='-pvol' ):
                                      if (len(cmdtab)>i+1) : 
                                            cli_vol_parent_vol=cmdtab[i+1]
                                            cli_ignore_arg=True
                                elif (cmdtab[i]=='-parent-snap' or cmdtab[i]=='-psnap' ):
                                      if (len(cmdtab)>i+1) : 
                                            cli_vol_parent_snap=cmdtab[i+1]
                                            cli_ignore_arg=True
                                elif (cmdtab[i]=='-parent-vserver' or cmdtab[i]=='-pvserver' ):
                                      if (len(cmdtab)>i+1) :
                                            cli_vol_parent_vserver=cmdtab[i+1]
                                            cli_ignore_arg=True
                                elif (cmdtab[i]=='-size'):
                                      if (len(cmdtab)>i+1) : 
                                            cli_vol_size=cmdtab[i+1]
                                            cli_ignore_arg=True
                                else:
                                     print_syntax_error("{0}: {1} : bad option".format(cmdtab[0], cmdtab[i]))
                                     cli_error=True
                                     break 
                          if (cli_vol_help):
                                    print_help_vol()
                          elif (cli_vol_show==True and cli_vol_create==False and cli_vol_delete==False and cli_vol_clone==False and cli_error==False ):
                                    ####################################################
                                    # Volume Show
                                    ####################################################
                                    requestFilter= {}
                                    if (len(cli_vol_volname)>0):
                                          requestFilter["name"] = cli_vol_volname
                                    if (len(cli_vol_aggrname)>0):
                                        requestFilter["aggregates.name"]=cli_vol_aggrname
                                    if (len(cli_vol_vserver)>0):
                                        requestFilter["svm.name"]=cli_vol_vserver
                                    if (cli_vol_list==True ):
                                          ontapRest.vol_print_list(hostname,user,password,requestFilter)
                                    else:
                                          ontapRest.vol_print_parameters(hostname,user,password,requestFilter)

                          elif (cli_vol_show==False and cli_vol_create==True and cli_vol_delete==False and cli_vol_clone==False and cli_error==False ):
                                    ####################################################
                                    # Volume Create 
                                    ####################################################
                                    # Check mandatory parameters
                                    if (len(cli_vol_volname)==0 or len(cli_vol_vserver)==0 or len(cli_vol_aggrname)==0):
                                          print_syntax_error("{0} {1}: syntax error: miss argument".format(cmdtab[0],cmdtab[1]))
                                          cli_error=True
                                    else: 
                                          # Set Default Volume Parameters
                                          volume_parameters={}
                                          volume_parameters["aggregates"]=[{ "name" : cli_vol_aggrname }]
                                          volume_parameters["name"]=cli_vol_volname
                                          volume_parameters["svm"]={"name": cli_vol_vserver}
                                          volume_parameters["guarantee"]={"type": "none"}
                                          volume_parameters["type"]="RW"
                                          # Add Parameters
                                          if (len(cli_vol_size)>0):
                                                volume_parameters["size"]=cli_vol_size
                                          ontapRest.vol_create_new(hostname,user,password,volume_parameters)
                          elif (cli_vol_show==False and cli_vol_create==False and cli_vol_delete==False and cli_vol_clone==True and cli_error==False ):
                                    ####################################################
                                    # Volume Clone 
                                    ####################################################
                                    # Check mandatory parameters
                                    if (len(cli_vol_volname)==0 or len(cli_vol_vserver)==0 or len(cli_vol_parent_vol)==0 or len(cli_vol_parent_snap)==0):
                                          print_syntax_error("{0} {1}: syntax error: miss argument".format(cmdtab[0],cmdtab[1]))
                                          cli_error=True
                                    else: 
                                          # Set Default Volume Parameters
                                          if (len(cli_vol_parent_vserver)==0):
                                                cli_vol_parent_vserver=cli_vol_vserver
                                          volume_clone={} 
                                          volume_clone["is_flexclone"]="true" 
                                          volume_clone["split_initiated"]="false" 
                                          volume_clone["parent_snapshot"]={"name": cli_vol_parent_snap } 
                                          volume_clone["parent_volume"]={"name": cli_vol_parent_vol } 
                                          volume_clone["parent_svm"]={"name": cli_vol_parent_vserver }
                                          volume_parameters={} 
                                          volume_parameters["name"]=cli_vol_volname 
                                          volume_parameters["svm"]={"name": cli_vol_vserver} 
                                          volume_parameters["clone"]=volume_clone 
                                          volume_parameters["guarantee"]={"type": "none"} 
                                          volume_parameters["type"]="RW"
                                          # Add Parameters
                                          ontapRest.vol_create_new(hostname,user,password,volume_parameters)
                          elif (cli_vol_show==False and cli_vol_create==False and cli_vol_delete==True and cli_vol_clone==False and cli_error==False ):
                                    ####################################################
                                    # Volume delete 
                                    ####################################################
                                    confirm='n'
                                    requestFilter= {}
                                    # Check Mandatroy parameter (vserver volumename)
                                    if (len(cli_vol_volname)==0 or len(cli_vol_vserver)==0): 
                                          print_syntax_error("{0} {1}: syntax error: miss argument".format(cmdtab[0],cmdtab[1]))
                                    else:
                                          if (len(cli_vol_volname)>0): requestFilter["name"] = cli_vol_volname
                                          if (len(cli_vol_aggrname)>0): requestFilter["aggregates.name"]=cli_vol_aggrname
                                          if (len(cli_vol_vserver)>0): requestFilter["svm.name"]=cli_vol_vserver
                                          volume_list=ontapRest.vol_get_uuid_list(hostname,user,password,requestFilter)
                                          if(len(volume_list)>0):
                                                print("Do you really want to delete this volumes ?")
                                                ontapRest.vol_print_list(hostname,user,password,requestFilter)
                                                confirm=input('ready to delete [y/n]? :')
                                                if ( confirm=='y'):
                                                      ontapRest.vol_delete_list(hostname,user,password,requestFilter)
                          else: 
                                cli_error=True
                                print_syntax_error("{0}: syntax error see help".format(cmdtab[0]))
                                print_help_vol()
                    ##################################################################################################
                    # command snapshot or snap 
                    elif (cmdtab[0]=='snapshot' or cmdtab[0]=='snap'):
                          cli_snap_snapname=''
                          cli_snap_volname=''
                          cli_snap_vserver=''
                          cli_snap_help=False
                          cli_snap_show=False
                          cli_snap_list=False
                          cli_snap_create=False
                          cli_snap_delete=False
                          cli_ignore_arg = False 
                          for i in range(1,len(cmdtab)):
                                if (cli_ignore_arg): 
                                      cli_ignore_arg=False
                                elif (cmdtab[i]=='help'):
                                      cli_snap_help=True
                                elif (cmdtab[i]=='create'):
                                      cli_snap_create=True
                                elif (cmdtab[i]=='show'):
                                      cli_snap_show=True
                                elif (cmdtab[i]=='delete'):
                                      cli_snap_delete=True
                                elif (cmdtab[i]=='-summary' or cmdtab[i]=='-sum' or cmdtab[i]=='-s'):
                                      cli_snap_list=True
                                elif (cmdtab[i]=='-volume'):
                                      if (len(cmdtab)>i+1):
                                            cli_snap_volname=cmdtab[i+1]
                                            cli_ignore_arg=True
                                elif (cmdtab[i]=='-vserver'):
                                      if (len(cmdtab)>i+1): 
                                            cli_snap_vserver=cmdtab[i+1]
                                            cli_ignore_arg=True
                                elif (cmdtab[i]=='-snapshot' or cmdtab[i]=='-snap' ):
                                      if (len(cmdtab)>i+1):
                                            cli_snap_snapname=cmdtab[i+1]
                                            cli_ignore_arg=True
                                else:
                                     print_syntax_error("{0}: bad option".format(cmdtab[i]))
                                     cli_error=True
                                     break 
                          if (cli_snap_help==True):
                                    print_help_snap()
                          elif (cli_snap_show==True and cli_snap_create==False and cli_snap_delete==False and cli_error==False) :
                                    ####################################################
                                    # Snapshot print
                                    ####################################################
                                    requestFilter= {}
                                    if (len(cli_snap_snapname)>0):
                                          requestFilter["name"] = cli_snap_snapname
                                    if (len(cli_snap_vserver)>0):
                                          requestFilter["svm.name"]=cli_snap_vserver
                                    if (len(cli_snap_volname)>0):
                                          requestFilter["volume.name"]=cli_snap_volname
                                    if(cli_snap_list==True):
                                          ontapRest.snap_print_list(hostname,user,password,requestFilter)
                                    else:
                                          ontapRest.snap_print_list(hostname,user,password,requestFilter)
                          elif (cli_snap_show==False and cli_snap_create==True and cli_snap_delete==False and cli_error==False) :
                                    ####################################################
                                    # Snapshot Create 
                                    ####################################################
                                    # Check mandatory parameters
                                    if (len(cli_snap_volname)==0 or len(cli_snap_vserver)==0 or len(cli_snap_snapname)==0):
                                          print_syntax_error("{0} {1}: syntax error: miss argument".format(cmdtab[0],cmdtab[1]))
                                          cli_error=True
                                    else: 
                                          # Set Default Volume Parameters
                                          volume_filter={}
                                          volume_filter["name"]=cli_snap_volname
                                          volume_filter["svm.name"]=cli_snap_vserver
                                          print_deb("Create Snapshot vserver: {0} volume: {1} snapname:{2}".format(cli_snap_vserver,cli_snap_volname,cli_snap_snapname))
                                          ontapRest.snap_create_on_multiple_vol(hostname,user,password,cli_snap_snapname,volume_filter)

                          elif (cli_snap_show==False and cli_snap_create==False and cli_snap_delete==True and cli_error==False) :
                                    ####################################################
                                    # Snapshot Delete 
                                    ####################################################
                                    # Check mandatory parameters
                                    if (len(cli_snap_volname)==0 or len(cli_snap_vserver)==0 or len(cli_snap_snapname)==0):
                                          print_syntax_error("{0} {1}: syntax error: miss argument".format(cmdtab[0],cmdtab[1]))
                                          cli_error=True
                                    else:
                                          requestFilter= {} 
                                          requestFilter["name"] = cli_snap_snapname 
                                          requestFilter["svm.name"]=cli_snap_vserver 
                                          requestFilter["volume.name"]=cli_snap_volname
                                          ontapRest.snap_delete_on_multiple_vol(hostname,user,password,requestFilter)

                          else: 
                                cli_error=True
                                print_syntax_error("{0}: syntax error see help".format(cmdtab[0]))
                                print_help_snap()
                    ##################################################################################################
                    # command aggregate | aggr 
                    elif (cmdtab[0]=='aggregate' or cmdtab[0]=='aggr'):
                          cli_aggr_aggrname='*'
                          cli_aggr_nodename='*'
                          cli_aggr_help=False
                          cli_aggr_show=False
                          cli_aggr_list=False
                          cli_ignore_arg = False 
                          for i in range(1,len(cmdtab)):
                                if (cli_ignore_arg): 
                                      cli_ignore_arg=False
                                elif (cmdtab[i]=='help'):
                                      cli_aggr_help=True
                                elif (cmdtab[i]=='show'):
                                      cli_aggr_show=True
                                elif (cmdtab[i]=='-summary' or cmdtab[i]=='-sum' or cmdtab[i]=='-s'):
                                      cli_aggr_list=True
                                elif (cmdtab[i]=='-aggregate' or cmdtab[i]=='-aggr' ):
                                      if (len(cmdtab)>i+1) :
                                            cli_aggr_aggrname=cmdtab[i+1]
                                            cli_ignore_arg=True
                                elif (cmdtab[i]=='-node'):
                                      if (len(cmdtab)>i+1) : 
                                            cli_aggr_nodename=cmdtab[i+1]
                                            cli_ignore_arg=True
                                else:
                                     print_syntax_error("{0}: bad option".format(cmdtab[i]))
                                     cli_error=True
                                     break 
                          requestFilter= {
                              "name":  cli_aggr_aggrname ,
                              "node":  cli_aggr_nodename
                          }
                          if (cli_aggr_help==True):
                              print_help_aggr()
                          elif (cli_aggr_show==True and cli_error == False ):
                                if (cli_aggr_list==True):
                                    ontapRest.aggr_print_list(hostname,user,password,requestFilter) 
                                else:
                                    ontapRest.aggr_print_list(hostname,user,password,requestFilter) 
      
                          else: 
                                cli_error=True
                                print_syntax_error("{0}: syntax error see help".format(cmdtab[0]))
                                print_help_aggr()
                    ##################################################################################################
                    # command vserver or svm 
                    elif (cmdtab[0]=='vserver' or cmdtab[0]=='svm'):
                          cli_svm_svmname='*'
                          cli_svm_help=False
                          cli_svm_show=False
                          cli_svm_list=False
                          cli_ignore_arg = False 
                          for i in range(1,len(cmdtab)):
                                if (cli_ignore_arg): 
                                      cli_ignore_arg=False
                                elif (cmdtab[i]=='help'):
                                      cli_svm_help=True
                                elif (cmdtab[i]=='show'):
                                      cli_svm_show=True
                                elif (cmdtab[i]=='-summary' or cmdtab[i]=='-sum' or cmdtab[i]=='-s'):
                                      cli_svm_list=True
                                elif (cmdtab[i]=='-vserver' or cmdtab[i]=='-svm' ):
                                      if (len(cmdtab)>i+1) :
                                            cli_svm_svmname=cmdtab[i+1]
                                            cli_ignore_arg=True
                                else:
                                     print_syntax_error("{0}: bad option".format(cmdtab[i]))
                                     cli_error=True
                                     break 
                          requestFilter= {
                              "name":  cli_svm_svmname ,
                          }
                          if (cli_svm_help==True):
                                print_help_svm()
                          elif (cli_svm_show==True and cli_error==False):
                                if(cli_svm_list==True):
                                    ontapRest.vserver_print_list(hostname,user,password,requestFilter)
                                else: 
                                    ontapRest.vserver_print_list(hostname,user,password,requestFilter)
                          else: 
                                cli_error=True
                                print_syntax_error("{0}: syntax error see help".format(cmdtab[0]))
                                print_help_svm()
                    ##################################################################################################
                    else: 
                        cli_error=True
                        print_syntax_error("Unknown command see help")
              else: 
                  cli_error=True
                  print_syntax_error("Syntax Error see help")
        if(cli_error==False and len(cmdline)!=0 and cmdtab[0]!='history' and cmdtab[0][0]!='!'):
              history.append(cmdline)
        # End loop
except KeyboardInterrupt:
        print ("Goodbye ONTAP")
        exit(0)
