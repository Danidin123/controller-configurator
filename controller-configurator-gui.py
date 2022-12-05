from ssl import SSLCertVerificationError
import requests
import urllib3
import time
import json
from getpass import getpass
import PySimpleGUI as sg


PSG_THEME="Reddit"
FONT = ("Arial", 14)
FONT2 = ("Arial", 12)
progress=0
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

####### neet to change it #######
CONTROLLER_FQDN="https://nlb-nginx-controller-671e2f13e6cc79f5.elb.eu-west-1.amazonaws.com"

def main_procedure():
  session = auth_controller()
  print("one  session", session)
  app_name = get_app_name()
  gw_name = f"{app_name}-gw"
  instance_group = get_instance_group()
  if instance_group == '1':
    ####### neet to change it #######
    instance_group = "test"
    environment = "test_env"
  elif instance_group == '2':
    ####### neet to change it #######
    instance_group = "wafprod"
    environment = "production"
  cert_choosen = get_cert(CONTROLLER_FQDN,session,environment)
  hostname,backed_url = hostname_backed_url()
  create_gw(session,hostname,gw_name,instance_group,environment,cert_choosen) #1
  create_app(session,app_name,environment) #2
  create_comp(session,app_name,gw_name,environment,backed_url) #3
  progress_barnew(25,"DONE!!!",5)

def progress_barnew(addition,status_update,sleep):
  global progress
  counter = 0
  sg.theme(PSG_THEME)  # please make your windows colorful
  column_to_be_centered = [[sg.Text('Configuring', key='status',font=FONT)],
                          [sg.ProgressBar(1, orientation='h', size=(40, 30), key='progress')],]
  layout = [[sg.VPush()],
            [sg.Push(), sg.Column(column_to_be_centered,element_justification='c'), sg.Push()],
            [sg.VPush()]]
  window = sg.Window('Controller Configurator', layout).Finalize()
  progress_bar = window['progress']
  status = window['status']
  while(counter < addition):
    time.sleep(sleep/addition)
    counter += 1
    ### GOOD config
    status.update(status_update)
    progress_bar.update(progress+counter,100)
  progress = progress + counter

def bad_config(status_update):
      sg.theme(PSG_THEME)  # please make your windows colorful
      column_to_be_centered = [[sg.Text('', key='status',font=FONT)],
                          [sg.ProgressBar(1, orientation='h', size=(40, 30), key='progress')],]
      layout = [[sg.VPush()],
            [sg.Push(), sg.Column(column_to_be_centered,element_justification='c'), sg.Push()],
            [sg.VPush()]]
      window = sg.Window('Controller Configurator', layout).Finalize()
      progress_bar = window['progress']
      status = window['status']
      status.update(status_update)
      progress_bar.update(visible=False)
      time.sleep(4)
      exit()

def get_app_name():
  sg.theme(PSG_THEME)  # please make your windows colorful
  layout = [[sg.Text('Enter the new APP name, and press Enter:',font=FONT)],
            [sg.Text('', size=(0, 0), font=FONT), sg.InputText(key='app_name', font=FONT2)],
            [sg.Submit(font=FONT2), sg.Exit(font=FONT2)]]
  window = sg.Window('Controller Configurator', layout, finalize=True)
  event, values = window.read()
  app_name = values['app_name']
  window.Close()
  return app_name

def get_instance_group():
  sg.theme(PSG_THEME)  # please make your windows colorful
  layout = [[sg.Text('Choose the instance group, and press Enter:', font=FONT)],
            [sg.Text('1: Test', font=FONT)],
            [sg.Text('2: Prod', font=FONT)],
            [sg.Text('', size=(0, 1), font=FONT), sg.InputText(key='instance_group', font=FONT)],
            [sg.Submit(), sg.Exit()]]
  window = sg.Window('Controller Configurator', layout, finalize=True)
  event, values = window.read()
  instance_group = values['instance_group']
  window.Close()
  return instance_group

def hostname_backed_url():
  sg.theme(PSG_THEME)  # please make your windows colorful
  layout = [[sg.Text('Enter the APP URL (GW hostname) , and press Enter:', font=FONT)],
            [sg.Text('', size=(0, 0), font=FONT), sg.InputText(key='hostname', font=FONT2)],
            [sg.Text('Enter the backend URL, and press Enter:', font=FONT)],
            [sg.Text('', size=(0, 0), font=FONT), sg.InputText(key='backed_url', font=FONT2)],
            [sg.Submit(), sg.Exit()]]
  window = sg.Window('Controller Configurator', layout, finalize=True)
  event, values = window.read()
  hostname = values['hostname']
  backed_url = values['backed_url']
  window.close()
  return hostname,backed_url

### Login to Controller                                 
def auth_controller():
    sg.theme(PSG_THEME)  # please make your windows colorful
    layout = [[sg.pin(sg.Text('Enter your user and password:',font=FONT))],
          [sg.Text('User:', size=(10),font=FONT2), sg.InputText(key='user',font=FONT2)],
          [sg.Text('Password: ', size=(10),font=FONT2), sg.InputText('', key='passd', password_char='*', font=FONT2)],
          [sg.StatusBar('', size=10, expand_x=True, key='Status',font=FONT2, background_color='light gray')],
          [sg.Submit(font=FONT2), sg.Exit(font=FONT2)]]
    window = sg.Window('Controller Configurator', layout, finalize=True, enable_close_attempted_event=True)
    window['Status'].my_bg = sg.theme_text_element_background_color()
    status = window['Status']
    status.update(visible=False)
    event, values = window.read()
    user = values['user']
    passd = values['passd']
    endpoint = f"{CONTROLLER_FQDN}/api/v1/platform/login"
    payload = {
        "credentials": {
            "type": "BASIC",
            "username": user,
            "password": passd
        }
    }
    payload=json.dumps(payload)
    headers = { 'content-type': "application/json" }
    session = requests.session()
    response = session.post(endpoint, data=payload, headers=headers, verify=False)
    if (200 <= response.status_code <= 210):
        status.update(visible=True)
        status.update("login successful")
        window['Status'].update(background_color='green')
        window.refresh()
        time.sleep(1)
        window.close()
    else:
        status.update(visible=True)
        status.update("Try to login again.....")
        window['Status'].update(background_color='red')
        window.refresh()
        time.sleep(3)
        window.close()
        exit()
    return session

### create new GW
def create_gw(session,hostname,gw_name,instance_group,environment,cert_choosen):
    payload = {
      "metadata": {
        "name": gw_name,
        "tags": []
      },
      "desiredState": {
        "ingress": {
          "uris": {
            hostname: {}
          },
          "placement": {
            "instanceGroupRefs": [
              {
                "ref": "/infrastructure/instance-groups/"f"{instance_group}"
              }
            ]
          },
          "tls": {
            "certRef": {
              "ref": cert_choosen
            },
            "preferServerCipher": "DISABLED"
          }
        },
        "configSnippets": {
          "httpSnippet": {
            "directives": [
              {
                "directive": "log_format",
                "args": [
                  "syslog-adasha",
                  "\"@timestamp\"=\"$time_iso8601\",",
                  "\"@source\"=\"$server_addr\",",
                  "\"hostname\"=\"$hostname\",",
                  "\"ip\"=\"$http_x_forwarded_for\",",
                  "\"client\"=\"$remote_addr\",",
                  "\"request_method\"=\"$request_method\",",
                  "\"scheme\"=\"$scheme\",",
                  "\"domain\"=\"$server_name\",",
                  "\"referer\"=\"$http_referer\",",
                  "\"request\"=\"$request_uri\",",
                  "\"args\"=\"$args\",",
                  "\"size\"=$body_bytes_sent,",
                  "\"status\"= $status,",
                  "\"responsetime\"=$request_time,",
                  "\"upstreamtime\"=\"$upstream_response_time\",",
                  "\"upstreamaddr\"=\"$upstream_addr\",",
                  "\"http_user_agent\"=\"$http_user_agent\",",
                  "\"https\"=\"$https\""
                ]
              }
            ]
          }
        }
      }
    }
    headers = { 'content-type': "application/json" }
    endpoint = f"{CONTROLLER_FQDN}/api/v1/services/environments/{environment}/gateways"
    payload=json.dumps(payload)
    response = session.post(endpoint, data=payload, headers=headers, verify=False)
    if (200 <= response.status_code <= 210):
      status_update = "OK - GW created"
      progress_barnew(25,status_update,5)
    else:
      status_update = "bad GW config"
      bad_config(status_update)

### create new App
def create_app(session,app_name,environment):
  payload = {
  "metadata": {
      "name": app_name,
      "tags": []
  },
  "desiredState": {}
      }
  headers = { 'content-type': "application/json" }
  endpoint = f"{CONTROLLER_FQDN}/api/v1/services/environments/{environment}/apps"
  payload=json.dumps(payload)
  response = session.post(endpoint, data=payload, headers=headers, verify=False)
  if (200 <= response.status_code <= 210):
    status_update = 'OK - APP created'
    progress_barnew(25,status_update,5)
  else:
    status_update = "bad APP config"
    bad_config(status_update)  

### create new Component
def create_comp(session,app_name,gw_name,environment,backed_url):
    payload = {
  "metadata": {
    "name": f"{app_name}-component",
    "tags": []
  },
  "desiredState": {
    "ingress": {
      "gatewayRefs": [
        {
          "ref": "/services/environments/"f"{environment}/gateways/{gw_name}"
        }
      ],
      "uris": {
        "/": {}
      }
    },
    "backend": {
      "ntlmAuthentication": "DISABLED",
      "preserveHostHeader": "DISABLED",
      "workloadGroups": {
        f"{app_name}-wl": {
          "loadBalancingMethod": {
            "type": "ROUND_ROBIN"
          },
          "uris": {
            backed_url: {
              "isBackup": False,
              "isDown": False,
              "isDrain": False
            }
          },
          "useServerPort": "DISABLED"
        }
      }
    },
    "logging": {
      "errorLog": "DISABLED",
      "accessLog": {
        "state": "DISABLED"
      }
    },
    "configSnippets": {
      "uriSnippets": [
        {
          "directives": [
            {
              "directive": "#",
              "args": [
                " Send logs to Logstash"
              ]
            },
            {
              "directive": "access_log",
              "args": [
                "syslog:server=10.32.6.56:516,tag=nginx_access",
                "syslog-adasha"
              ]
            },
            {
              "directive": "error_log",
              "args": [
                "syslog:server=10.32.6.56:516,tag=nginx_error"
              ]
            },
            {
              "directive": "#",
              "args": [
                " Send WAF logs to Grafana"
              ]
            },
            {
              "directive": "app_protect_security_log",
              "args": [
                "/etc/nginx/custom_log_format.json",
                "syslog:server=10.32.6.56:515"
              ]
            }
          ]
        }
      ]
    },
    "security": {
      "strategyRef": {
        "ref": "/security/strategies/default_policy_with_xff"
      },
      "waf": {
        "isEnabled": True
      }
    }
  }
}
    headers = { 'content-type': "application/json" }
    endpoint = f"{CONTROLLER_FQDN}/api/v1/services/environments/{environment}/apps/{app_name}/components"
    payload=json.dumps(payload)
    response = session.post(endpoint, data=payload, headers=headers, verify=False)
    if (200 <= response.status_code <= 210):
      status_update = 'OK - Component created'
      progress_barnew(25,status_update,5)
    else:
      status_update = 'bad Component config'
      bad_config(status_update)

def get_cert(CONTROLLER_FQDN,session,environment):
  headers = { 'content-type': "application/json" }
  endpoint = f"{CONTROLLER_FQDN}/api/v1/services/environments/{environment}/certs"
  response = session.get(endpoint,  headers=headers, verify=False).json()
  cert_items = response['items']
  certs_adasha = {}
  for cert in cert_items:
    certs_adasha[cert['currentStatus']['certMetadata'][0]['commonName']]=cert['metadata']['links']['rel'].replace("/api/v1","") 
  sg.theme(PSG_THEME)  # please make your windows colorful
  layout = [[sg.Text('Choose the CERT from the list, and press Enter:', font=FONT)],
            [sg.Combo(list(certs_adasha.keys()), enable_events=True, key='CERT', font=FONT)]]
  window = sg.Window('Controller Configurator', layout)
  event, values = window.Read()
  time.sleep(1)
  window.Close()
  return certs_adasha[values['CERT']]

main_procedure()
