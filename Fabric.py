#!/bin/python3.7
# coding: utf-8

import sys
import argparse
import pdb
import yaml
import os
from time import gmtime, strftime , localtime
import socks
from logging import Logger
import re


from acitoolkit.acitoolkit import Session
from acitoolkit.aciphysobject import Node
from acitoolkit.acitoolkit import *
import pwd 

import json
from pprint import pprint as ppr

sys.path.insert(0,'/home/x112097/py3')
from getHosts import *
from getsec import *
import cache as cc

import websocket
websocket.enableTrace(False)

TSK="/home/x112097/CONNEXION/pass.db"

socks.log=Logger(None)

hash_of_conf_files={'assu':'/home/x112097/py3/aci/conf/assu_conf.yml','bddf':'/home/x112097/py3/aci/conf/RET-CONF/bddf_conf.yml','cloud':'\
/home/x112097/py3/aci/conf/plt_cloud_conf.yml','bigdata':'/home/x112097/py3/aci/conf/plt_bigdata_conf.yml','shared':'/home/x112097/py/dmo/\
dmoConf/aci/plt_shared_conf.yml','workplace':'/home/x112097/py3/aci/conf/plt_workplace_conf.yml','pfhr':'/home/x112097/py3/aci/conf/PFHR-CONF/pfhr_conf.yml'\
,'gbis':'/home/x112097/py3/aci/conf/MKT-CONF/gbis_conf.yml'}

PROXIES={'https':'socks5://127.0.0.1:7777','http':'socks5://127.0.0.1:7777'}


class Loader(yaml.SafeLoader):
	def __init__(self, stream):
		self._root = os.path.split(stream.name)[0]
		super(Loader, self).__init__(stream)

	def include(self, node):
		filename = os.path.join(self._root, self.construct_scalar(node))
		with open(filename, 'r') as f:
			return yaml.load(f)

Loader.add_constructor('!include', Loader.include)

def initCred():
	username=pwd.getpwuid(os.getuid()).pw_name
	tsk=secSbe(TSK)
	return {'username':username,'passwd':tsk.tac}

class Fabric(object):
	def __init__(self,name='BDDF',proxies=PROXIES,connect=True): 
		self.name=name
		self.proxies=proxies
		self.config_file=self.get_conf_filename(self.name)
		self.config=self.getInfoYaml()
		self.hosts=Hosts(dump=get_last_dump_host(PATH_HOST))
		self.sites=self.get_sites()
		self.apics=self.getApics()
		self.mscs=self.getMsc()
		self.authDomain=self.getAuthAll()
		
		if connect:
			self.sessions=self.getSessions()
		
	def getInfoYaml(self):
		try:
			with open(self.config_file,'r') as file:
				config_yaml=yaml.load(file,Loader)
		except TypeError as e:
			print("Fabric '%s' is unknown"%self.name,file=sys.stderr)
			print("Known fabrics: '%s'")
			for (name,conf) in hash_of_conf_files.items():
				print(" - %s (conf file: %s)"%(name,conf),file=sys.stderr)
			print()
			print("Please edit 'hash_of_conf_file' to add new fabrics")
			sys.exit(1)
			
		return config_yaml
		
		
	def getAuthAll(self):
		auth={}
		for site in self.config['sites']:
			try:
				auth[site['name']]=site['authdomain']
			except KeyError as E:
				auth[site['name']]=None
		
		return auth
			

		
	def getSessions(self):
		sessions={}
		Cred=initCred()
		
		for site in self.sites:
			url="https://"+self.apics[site][0]['ip']
			username=Cred['username']
			if self.authDomain[site]:
				username='apic:'+self.authDomain[site]+'\\'+username
				
			sessions[site] = Session(url, username, Cred['passwd'],proxies=self.proxies)
			resp = sessions[site].login()
			
			indice=1
			while not resp.ok:
				try:
					print('%% Could not login to APIC for site',site,'(APIC:)',self.apics[site][indice]['name'],'=>URL',url,file=sys.stderr)
					print('Trying an another APIC:',self.apics[site][indice]['name'],'=>Fabric:',self.name)
					url="https://"+self.apics[site][indice]['ip']
					username=Cred['username']
					if self.authDomain[site]:
						username='apic:'+self.authDomain[site]+'\\'+username
						
					sessions[site] = Session(url, username, Cred['passwd'],proxies=self.proxies)
					resp = sessions[site].login()
					indice+=1

				except IndexError:
					print('%% All APIC are unreachable:',site,'=>Fabric:',self.name,file=sys.stderr)
					
				
			
		return sessions
				
	def get_sites(self):
		try:
			return [ site['name'] for site in self.config['sites'] ]
			
		except KeyError as e:
			print(e,file=sys.stderr)
			print("Verify config file:%s"%self.config_file, file=sys.stderr)
			sys.exit(1)
			
			
	def getApics(self):
		apcs={}
		
		for site in self.config['sites']:
			apcs[site['name']]=[ {'name':apc__ , 'ip': self.hosts.getIP(apc__)[0] } for apc__ in site['apcs'] ]
		
		return apcs
		
	def getMsc(self):

		
		try:
			mscs=[ { 'name':  self.hosts.getIP(msc['ip'])[0]   , 'ip': msc['ip'] } for msc in  self.config['msc']['servers'] ]
		except KeyError as E:
			return []
			
		return mscs
		
	def get_conf_filename(self,name):
		name=name.lower()
		try:
				return hash_of_conf_files[name]
		except KeyError as e:
				print("Fabric '%s' is unknown"%name,file=sys.stderr)
				print("Known fabrics: '%s'")
				for (name,conf) in CONFIG_YAML_FILE.items():
						print(" - %s (conf file: %s)"%(name,conf),file=sys.stderr)

				print()
				print("Please edit 'hash_of_conf_file' to add new fabrics")
				sys.exit(1)


		return config_yaml
		
	@staticmethod
	def getExistingSite(name):
		try:
			configFile=hash_of_conf_files[name]
			with open(configFile,'r') as file_yml:
				Info=yaml.load(file_yml,Loader)
				return [ site['name'] for site in Info['sites'] ]
			
		except KeyError as e:
			print(e,file=sys.stderr)
			print("Verify dict file:hash_of_conf_files", file=sys.stderr)
			raise(e)
			
	@staticmethod
	def getFabricName():
		return list(hash_of_conf_files.keys())
	
	@staticmethod
	def print_tenants(tenants):
	
		if isinstance(tenants,list):
			for tenant in tenants:
				print('name:',tenant.name,'\t\tdescr:',tenant.descr)
		elif isinstance(tenants,dict):
			for site in tenants:
				print('Site:',site)
				for tenant in tenants[site]:
					print('\tname:',tenant.name,'\t\tdescr:',tenant.descr)
			
	@staticmethod
	def parsingDnInt(dn):
		Slash=pp.Suppress(pp.Literal('/'))
		Net=(pp.Word(pp.nums).addCondition(lambda tokens:int(tokens[0]) <=32 and int(tokens[0]) >= 0 ))
		octet = (pp.Word(pp.nums).addCondition(lambda tokens:int(tokens[0]) <256 and int(tokens[0]) >= 0 ))
		ipAddress=pp.Combine(octet + ('.'+octet)*3)
		ipAddressNet=pp.Combine(ipAddress+pp.Literal('/')+Net)
		Node_=(pp.Suppress(pp.Literal('node-'))+pp.Word(pp.alphanums+'_-')).setResultsName('node')
		Skip=pp.Suppress(pp.SkipTo(pp.Literal('/dom-'),include=True))
		Tenant=pp.Word(pp.alphanums+'-_').setResultsName('tenant')
		Vrf=(pp.Suppress(pp.Literal(':'))+pp.Word(pp.alphanums+'_-')).setResultsName('vrf')
		Interface=(pp.Suppress(pp.Literal('if-['))+pp.Word(pp.alphanums+'_-/.')+pp.Suppress(pp.Literal(']'))).setResultsName('if')
		IP=(pp.Suppress(pp.Literal('addr-['))+pp.MatchFirst([ipAddressNet,ipAddress])+pp.Suppress(']')).setResultsName('ip')
		topology_prefix=pp.Suppress(pp.Literal('topology/pod-')+pp.Word(pp.nums,exact=1))
		IfDn=topology_prefix+Slash+Node_+Slash+Skip+Tenant+pp.Optional(Vrf,default=['GRT'])+Slash+Interface+Slash+IP
		
		try:
			resultat=IfDn.parseString(dn).asDict()
		except pp.ParseException as E:
			pdb.set_trace()
			print(E)
			
		return resultat
		
	def getTenants(self,site=""):
		if site:
			tenants=Tenant.get(self.sessions[site])
		else:
			tenants={}
			for site__ in self.sites:
				tenants[site__]=Tenant.get(self.sessions[site__])
				
		return tenants
		
	def getEpgs(self,site=""):
	
		
		if site:
			epgs_res=[]
			tenants=Tenant.get(self.sessions[site])
			for tenant in tenants:
				apps = AppProfile.get(self.sessions[site], tenant)
				for app in apps:
					epgs = EPG.get(self.sessions[site], app, tenant)
					for epg in epgs:
						epgs_res.append([tenant.name, app.name, epg.name,epg.name.replace('VLAN_','').replace('_EPG','')])
			
			
			
			
			
			
		else:
			epgs_res={}
			for site__ in self.sites:
				tenants=Tenant.get(self.sessions[site__])
				epgs_res[site__]=[]
				for tenant in tenants:
					apps = AppProfile.get(self.sessions[site__], tenant)
					for app in apps:
						epgs = EPG.get(self.sessions[site__], app, tenant)
						for epg in epgs:
							epgs_res[site__].append([tenant.name, app.name, epg.name,epg.name.replace('VLAN_','').replace('_EPG','')])
						
		return epgs_res
	
	def getBds(self,site=""):
		
		Bds={}
		ImportantAttr=['pcTag','scope','mac','vmac']
		ChildrenImportAttr={ 'fvRsCtx' : ['tnFvCtxName'] , 'fvSubnet' : ['ip'] }
		if site:
			resp=self.sessions[site].get('/api/node/class/fvBD.json?rsp-subtree=full')
			InfoBds=json.loads(resp.text)['imdata']
			for bd in InfoBds:
				
				name=bd['fvBD']['attributes']['dn'].replace('uni/','')

				Bds[name]={ Attr:bd['fvBD']['attributes'][Attr] for Attr in ImportantAttr}
				ChildrenInfo=list(filter(lambda x: list(x.keys())[0] in ChildrenImportAttr , bd['fvBD']['children'] ) )
				ChildrenInfoFiltered=[ { list(attr.keys())[0]: { intraAttr.replace('tnFvCtxName','vrf'):info  for ( intraAttr,info ) in attr[ list(attr.keys())[0] ]['attributes'].items() if intraAttr in ChildrenImportAttr[list(attr.keys())[0]]  } } for attr in ChildrenInfo ]
				
				Bds[name]['l3']=ChildrenInfoFiltered
	
			
		else:
			for site__ in self.sites:
				Bds[site__]={}
				resp=self.sessions[site__].get('/api/node/class/fvBD.json?rsp-subtree=full')
				InfoBds=json.loads(resp.text)['imdata']
				for bd in InfoBds:
					
					name=bd['fvBD']['attributes']['dn'].replace('uni/','')
	
					Bds[site__][name]={ Attr:bd['fvBD']['attributes'][Attr] for Attr in ImportantAttr}
					ChildrenInfo=list(filter(lambda x: list(x.keys())[0] in ChildrenImportAttr , bd['fvBD']['children'] ) )
					ChildrenInfoFiltered=[ { list(attr.keys())[0]: { intraAttr.replace('tnFvCtxName','vrf'):info  for ( intraAttr,info ) in attr[ list(attr.keys())[0] ]['attributes'].items() if intraAttr in ChildrenImportAttr[list(attr.keys())[0]]  } } for attr in ChildrenInfo ]
					
					Bds[site__][name]['l3']=ChildrenInfoFiltered
							
		return Bds
		
	def getContract(self,site=""):
		Cts={}
		tenantsName=[]
		if site:
			tenants=Tenant.get(self.sessions[site])
			for tenant in tenants:
				tenantsName.append(tenant.name)
			tenantsDeep = Tenant.get_deep(self.sessions[site], names=tenantsName,)
			for tenantDeep in tenantsDeep:
				contracts = tenantDeep.get_children(Contract)
				Ctx= tenantDeep.get_children(Context)
				Filters__=tenantDeep.get_children(Filter)
				Cts[tenantDeep.name]=[]
				for contract in contracts:
					pdb.set_trace()
					Cts[tenantDeep.name].append(contract)
				for filter__ in Filters__:
					#pdb.set_trace()
					filter__ 
		else:
			for site__ in self.site:
				Cts[site__]={tenant.name:[]}
				tenants=Tenant.get(self.sessions[site__])
				for tenant in tenants:
					contracts = Contract.get(self.sessions[site__], tenant)
					for contract in contracts:
						Cts[site__][tenant.name].append(contract.name)
						pdb.set_trace()
		
		return Cts
		
	@staticmethod
	def extractNodeFromDn(dn__):
		Node__=pp.Suppress(pp.Literal('node-'))+pp.Word(pp.alphanums+'-_:')
		return Node__.searchString(dn__).asList()[0][0]
		
	@staticmethod
	def extractDomFromDn(dn__):
		Dom=pp.Suppress(pp.Literal('dom-'))+pp.Word(pp.alphanums+'-_:')
		dom=Dom.searchString(dn__).asList()[0][0]
		
		return dom
		
	@staticmethod
	def extractTenantFromDn(dn__):
		Tn=pp.Suppress(pp.Literal('tn-'))+pp.Word(pp.alphanums)
		return Tn.searchString(dn__).asList()[0][0]
		
	@staticmethod
	def extractInfoFromBoxBracket(dn__):
		Info=pp.Suppress(pp.Literal('['))+pp.Word(pp.alphanums+'-/.:')+pp.Suppress(pp.Literal(']'))
		return Info.searchString(dn__).asList()[0][0]
		
	@staticmethod
	def extractPathFromDn(dn__):
		Path=pp.Suppress(pp.Literal('/protpaths-'))+pp.Word(pp.alphanums+'-.:')+pp.Suppress(pp.Literal('/'))
		return Path.searchString(dn__).asList()[0][0]
		
	@staticmethod
	def getNodeFromeCache(name=""):
		if not name:
			cacheNode=cc.Cache('ACI_ALL_ALLSITE_NODE')
			
			if cacheNode.isOK():
				return cacheNode.getValue()
		else:
			cacheNode=cc.Cache('ACI_'+name+'_ALLSITE_NODE')
			
			if cacheNode.isOK():
				return cacheNode.getValue()
			
	@staticmethod
	def getEndpointFromeCache(name,site=""):
		if not site:
			cacheEP=cc.Cache('ACI_'+name+'_ALLSITE_EP')
			if cacheEP.isOK():
				return cacheEP.getValue()
			
		cacheEP=cc.Cache('ACI_'+name+'_'+site+'_EP')
		
		if cacheEP.isOK():
			return cacheEP.getValue()
			
	@staticmethod		
	def getIfDescriptionFromeCache(name,site=""):
		if not site:
			cacheDesc=cc.Cache('ACI_'+name+'_ALLSITE_INT_DESCRIPTION')
			if cacheDesc.isOK():
				return cacheDesc.getValue()
			
		cacheDesc=cc.Cache('ACI_'+name+'_'+site+'_INT_DESCRIPTION')
		
		if cacheDesc.isOK():
			return cacheDesc.getValue()
			
	def getPortchannelFromeCache(name,site=""):

		if not site:
			cachePo=cc.Cache('ACI_'+name+'_ALLSITE_PORTCHANNEL')
			if cachePo.isOK():
				return cachePo.getValue()
			
		cachePo=cc.Cache('ACI_'+name+'_'+site+'_PORTCHANNEL')
		
		if cachePo.isOK():
			return cachePo.getValue()
			
	def getHealth(self,site=""):
		Healths={}
		
		if site:
			respTotal=self.sessions[site].get('/api/node/class/fabricHealthTotal.json')
			respNode=self.sessions[site].get('/api/node/class/fabricNodeHealth5min.json')
			respTn=self.sessions[site].get('/api/node/class/fvOverallHealth15min.json')
			HealthTotal=json.loads(respTotal.text)['imdata'][0]['fabricHealthTotal']['attributes']['cur']
			InfoHealthNode= json.loads(respNode.text)['imdata']
			InfoHealthTenant= json.loads(respTn.text)['imdata']
			HealthNode={}
			HealthTenant={}
			for equipment in InfoHealthNode:
				dnCur=equipment['fabricNodeHealth5min']['attributes']['dn']
				HealthCur=equipment['fabricNodeHealth5min']['attributes']['healthAvg']
				name=self.extractNodeFromDn(dnCur)
				HealthNode[name]=HealthCur
			for tenantInfo in InfoHealthTenant:
				dnCur=tenantInfo['fvOverallHealth15min']['attributes']['dn']
				HealthCur=tenantInfo['fvOverallHealth15min']['attributes']['healthAvg']
				name=self.extractTenantFromDn(dnCur)
				HealthTenant[name]=HealthCur
			
			Healths={'fabric':HealthTotal,'nodes':HealthNode,'tenant':HealthTenant}
		else:
			for site__ in self.sites:
				respTotal=self.sessions[site__].get('/api/node/class/fabricHealthTotal.json')
				respNode=self.sessions[site__].get('/api/node/class/fabricNodeHealth5min.json')
				respTn=self.sessions[site__].get('/api/node/class/fvOverallHealth15min.json')
				HealthTotal=json.loads(respTotal.text)['imdata'][0]['fabricHealthTotal']['attributes']['cur']
				InfoHealthNode= json.loads(respNode.text)['imdata']
				InfoHealthTenant= json.loads(respTn.text)['imdata']
				HealthNode={}
				HealthTenant={}
				for equipment in InfoHealthNode:
					dnCur=equipment['fabricNodeHealth5min']['attributes']['dn']
					HealthCur=equipment['fabricNodeHealth5min']['attributes']['healthAvg']
					name=self.extractNodeFromDn(dnCur)
					HealthNode[name]=HealthCur
				for tenantInfo in InfoHealthTenant:
					dnCur=tenantInfo['fvOverallHealth15min']['attributes']['dn']
					HealthCur=tenantInfo['fvOverallHealth15min']['attributes']['healthAvg']
					name=self.extractTenantFromDn(dnCur)
					HealthTenant[name]=HealthCur
					
			
				Healths[site__]={'fabric':HealthTotal,'nodes':HealthNode,'tenant':HealthTenant}
		
		return Healths
		
	def getVersion(self,site=""):
		
		InfoVer={}
		if site:
			#resp=self.sessions[site].get('/api/node/class/topSystem.json?query-target=subtree&target-subtree-class=topSystem,eqptCh,firmwareRunning,firmwareCtrlrRunning,maint,maintUpgJob')
			#resp=self.sessions[site].get('/api/node/class/topSystem.json')
			resp=self.sessions[site].get('/api/node/class/firmwareRunning.json')
			InfoVerData = json.loads(resp.text)['imdata']
			for equipment in InfoVerData:
				dnCur=equipment ['firmwareRunning']['attributes']['dn']
				version=equipment ['firmwareRunning']['attributes']['version']
				name=self.extractNodeFromDn(dnCur)
				InfoVer[name]=version
			respCtrl=self.sessions[site].get('/api/node/class/firmwareCtrlrRunning.json')
			InfoVerDataCtrl= json.loads(respCtrl.text)['imdata']
			for equipment in InfoVerDataCtrl:
				dnCur=equipment ['firmwareCtrlrRunning']['attributes']['dn']
				version=equipment ['firmwareCtrlrRunning']['attributes']['version']
				name=self.extractNodeFromDn(dnCur)
				InfoVer[name]=version
			
			
		else:
			InfoVer={}
			for site__ in self.sites:
				InfoVer[site__]={}
				resp=self.sessions[site__].get('/api/node/class/firmwareRunning.json')
				respCtrl=self.sessions[site__].get('/api/node/class/firmwareCtrlrRunning.json')
				InfoVerData = json.loads(resp.text)['imdata']
				InfoVerDataCtrl= json.loads(respCtrl.text)['imdata']
				for equipment in InfoVerData:
					dnCur=equipment ['firmwareRunning']['attributes']['dn']
					version=equipment ['firmwareRunning']['attributes']['version']
					name=self.extractNodeFromDn(dnCur)
					InfoVer[site__][name]=version
				for equipment in InfoVerDataCtrl:
					dnCur=equipment ['firmwareCtrlrRunning']['attributes']['dn']
					version=equipment ['firmwareCtrlrRunning']['attributes']['version']
					name=self.extractNodeFromDn(dnCur)
					InfoVer[site__][name]=version
		return InfoVer
		
	def getIntStatus(self,site=""):
		
		InfoIf={}
		ImportantAttr=['operDuplex','operMdix','operMode','operSpeed','operSt','usage']
		if site:
			resp=self.sessions[site].get('/api/node/class/ethpmPhysIf.json')
			InfoifData = json.loads(resp.text)['imdata']
			for ifCur in InfoifData:
				ifDataCur=ifCur['ethpmPhysIf']['attributes']
				nodeCur=self.extractNodeFromDn(ifDataCur['dn'])
				ifIdCur=self.extractInfoFromBoxBracket(ifDataCur['dn'])
				if nodeCur in InfoIf:
					InfoIf[nodeCur][ifIdCur]={attr__:ifDataCur[attr__] for attr__ in ImportantAttr}
				else:
					InfoIf[nodeCur]={ifIdCur:{attr__:ifDataCur[attr__] for attr__ in ImportantAttr}}
			
			
		else:
			InfoIf={}
			for site__ in self.sites:
				resp=self.sessions[site__].get('/api/node/class/ethpmPhysIf.json')
				InfoifData = json.loads(resp.text)['imdata']
				InfoIf[site__]={}
				for ifCur in InfoifData:
					ifDataCur=ifCur['ethpmPhysIf']['attributes']
					nodeCur=self.extractNodeFromDn(ifDataCur['dn'])
					ifIdCur=self.extractInfoFromBoxBracket(ifDataCur['dn'])
					if nodeCur in InfoIf[site__]:
						InfoIf[site__][nodeCur][ifIdCur]={attr__:ifDataCur[attr__] for attr__ in ImportantAttr}
					else:
						InfoIf[site__][nodeCur]={ifIdCur:{attr__:ifDataCur[attr__] for attr__ in ImportantAttr}}
		return InfoIf
	
	def getIntDescription(self,site=""):
		
		InfoIf={}
		
		ImportantAttr=['operDuplex','operMdix','operMode','operSpeed','operSt','usage']
		if site:
			nodes__=self.getNodeBrief(site=site)
			
			for node__ in nodes__:
				resp=self.sessions[site].get(f'/api/mo/topology/pod-1/node-{node__}.json?query-target=subtree&target-subtree-class=l1PhysIf')
				InfoifData = json.loads(resp.text)['imdata']
				InfoIf[node__]={}
				for ifCur in InfoifData:
					ifDataCur=ifCur['l1PhysIf']['attributes']
					InfoIf[node__][ifDataCur['id']]=ifDataCur['descr']
					#ppr({'node':node__,'id':ifDataCur['id'] , 'descr':ifDataCur['descr']})
			
		else:
			for site__ in self.sites:
				nodes__=self.getNodeBrief(site=site__)
				InfoIf[site__]={}
				for node__ in nodes__:
					resp=self.sessions[site__].get(f'/api/mo/topology/pod-1/node-{node__}.json?query-target=subtree&target-subtree-class=l1PhysIf')
					InfoifData = json.loads(resp.text)['imdata']
					InfoIf[site__][node__]={}
					for ifCur in InfoifData:
						ifDataCur=ifCur['l1PhysIf']['attributes']
						InfoIf[site__][node__][ifDataCur['id']]=ifDataCur['descr']
						ppr({'node':node__,'id':ifDataCur['id'] , 'descr':ifDataCur['descr']})

		
		return InfoIf
		
	def getEndpoint(self,site=""):
		
		EPs={}
		if site:
			endpoints=Endpoint.get(self.sessions[site])
			for ep in endpoints:
				epg = ep.get_parent()
				app_profile = epg.get_parent()
				tenant = app_profile.get_parent()
				infoIfCur=ep.if_name
				if not infoIfCur:
					continue
				if re.search('^eth ',infoIfCur):
					infoIfCurList=infoIfCur.split('/')
					nodeId=infoIfCurList[1]
					IfCur='eth'+infoIfCurList[2]+'/'+infoIfCurList[3]
				else:
					IfCur=infoIfCur
					nodeId=self.extractPathFromDn(ep.if_dn)
					
				if nodeId in EPs:
					if IfCur in EPs[nodeId]:
						EPs[nodeId][IfCur].append([ tenant.name,app_profile.name,epg.name,ep.mac, ep.ip , ep.encap ])
					else:
						EPs[nodeId][IfCur]=[[ tenant.name,app_profile.name,epg.name,ep.mac, ep.ip , ep.encap ]]
				else:
					EPs[nodeId]={ IfCur: [[ tenant.name,app_profile.name,epg.name,ep.mac, ep.ip , ep.encap ]] }
				
			
			
		else:
			for site__ in self.sites:
				endpoints=Endpoint.get(self.sessions[site__])
				EPs[site__]={}
				for ep in endpoints:
					epg = ep.get_parent()
					app_profile = epg.get_parent()
					tenant = app_profile.get_parent()
					infoIfCur=ep.if_name
					if not infoIfCur:
						continue
					try:
						if re.search('^eth ',infoIfCur):
							infoIfCurList=infoIfCur.split('/')
							nodeId=infoIfCurList[1]
							IfCur='eth'+infoIfCurList[2]+'/'+infoIfCurList[3]
						else:
							IfCur=infoIfCur
							nodeId=self.extractPathFromDn(ep.if_dn)
					except TypeError as E:
						pdb.set_trace()
						print(E)
						
					if nodeId in EPs[site__]:
						if IfCur in EPs[site__][nodeId]:
							EPs[site__][nodeId][IfCur].append([ tenant.name,app_profile.name,epg.name,ep.mac, ep.ip , ep.encap ])
						else:
							EPs[site__][nodeId][IfCur]=[[ tenant.name,app_profile.name,epg.name,ep.mac, ep.ip , ep.encap ]]
					else:
						EPs[site__][nodeId]={ IfCur: [[ tenant.name,app_profile.name,epg.name,ep.mac, ep.ip , ep.encap ]] }
						
						
		return EPs
		
	def getPortchannel(self,site=""):
		
		
		InfoIf={}
		
		ImportantAttr=['operDuplex','operMdix','operMode','operSpeed','operSt','usage']
		if site:
			nodes__=self.getNodeBrief(site=site)
			
			for node__ in nodes__:
				resp=self.sessions[site].get(f'/api/mo/topology/pod-1/node-{node__}/sys.json?query-target=subtree&target-subtree-class=pcAggrIf&rsp-subtree=children&rsp-subtree-class=ethpmAggrIf,pcRsMbrIfs')
				InfoifData = json.loads(resp.text)['imdata']
				InfoIf[node__]={}
				for ifCur in InfoifData:
					ifDataCur=ifCur['pcAggrIf']['attributes']
					ifDataMember= ifCur['pcAggrIf']['children']
					dn=ifDataCur['dn']
					poId=ifDataCur['id']
					name=ifDataCur['name']
					mode=ifDataCur['mode']
					IfMember=[]
					for member in ifDataMember:
						if 'pcRsMbrIfs' in member:
							infoMemberCur=member['pcRsMbrIfs']['attributes']
						elif 'ethpmAggrIf' in member:
							continue
						tDn=infoMemberCur['tDn']
						state=infoMemberCur['state']
						ifCur=self.extractInfoFromBoxBracket(tDn)
						IfMember.append([ifCur,state])
					InfoIf[node__][name]={'id':poId , 'mode':mode ,'members':{ifMbkey[0]:{'state':ifMbkey[1]} for ifMbkey in IfMember} }
			
		else:
			for site__ in self.sites:
				nodes__=self.getNodeBrief(site=site__)
				InfoIf[site__]={}
				for node__ in nodes__:
					resp=self.sessions[site__].get(f'/api/mo/topology/pod-1/node-{node__}/sys.json?query-target=subtree&target-subtree-class=pcAggrIf&rsp-subtree=children&rsp-subtree-class=ethpmAggrIf,pcRsMbrIfs')
					InfoifData = json.loads(resp.text)['imdata']
					InfoIf[site__][node__]={}
					for ifCur in InfoifData:
						ifDataCur=ifCur['pcAggrIf']['attributes']
						ifDataMember= ifCur['pcAggrIf']['children']
						dn=ifDataCur['dn']
						poId=ifDataCur['id']
						name=ifDataCur['name']
						mode=ifDataCur['mode']
						IfMember=[]
						for member in ifDataMember:
							if 'pcRsMbrIfs' in member:
								infoMemberCur=member['pcRsMbrIfs']['attributes']
							elif 'ethpmAggrIf' in member:
								continue
							tDn=infoMemberCur['tDn']
							state=infoMemberCur['state']
							ifCur=self.extractInfoFromBoxBracket(tDn)
							IfMember.append([ifCur,state])
						InfoIf[site__][node__][name]={'id':poId , 'mode':mode ,'members':{ifMbkey[0]:{'state':ifMbkey[1]} for ifMbkey in IfMember} }
						
		return InfoIf
		
	def getRoute(self,site=""):
		
		Ribs={}
		if site:
			resp=self.sessions[site].get('/api/node/class/uribv4Route.json?rsp-subtree=full')
			InfoRib= json.loads(resp.text)['imdata']
			for entry in InfoRib:
				dn=entry['uribv4Route']['attributes']['dn']
				dom=self.extractDomFromDn(dn)
				node__=self.extractNodeFromDn(dn)
				print(dn)
				prefix=entry['uribv4Route']['attributes']['prefix']
				nexthops=[ {'protocol':nh['uribv4Nexthop']['attributes']['routeType'] ,'vrf': nh['uribv4Nexthop']['attributes']['vrf'] ,'if': nh['uribv4Nexthop']['attributes']['if'], 'nexthop':  entry['uribv4Route']['children'][0]['uribv4Nexthop']['attributes']['addr'].split('/')[0] } for nh in entry['uribv4Route']['children'] ]
				nexthops.sort(key=lambda x:x['nexthop'])
				if node__ in Ribs:
					if dom in Ribs[node__]:
						Ribs[node__][dom][prefix]=nexthops
					else:
						Ribs[node__][dom]={prefix:nexthops}
				else:
					Ribs[node__]={dom: {prefix:nexthops} }
						
		else:
			for site__ in self.sites:
				Ribs[site__]={}
				resp=self.sessions[site__].get('/api/node/class/uribv4Route.json?rsp-subtree=full')
				InfoRib= json.loads(resp.text)['imdata']
				for entry in InfoRib:
					dn=entry['uribv4Route']['attributes']['dn']
					dom=self.extractDomFromDn(dn)
					node__=self.extractNodeFromDn(dn)
					prefix=entry['uribv4Route']['attributes']['prefix']
					nexthops=[ {'protocol':nh['uribv4Nexthop']['attributes']['routeType'] ,'vrf': nh['uribv4Nexthop']['attributes']['vrf'] ,'if': nh['uribv4Nexthop']['attributes']['if'], 'nexthop':  entry['uribv4Route']['children'][0]['uribv4Nexthop']['attributes']['addr'].split('/')[0] } for nh in entry['uribv4Route']['children'] ]
					nexthops.sort(key=lambda x:x['nexthop'])
					if node__ in Ribs[site__]:
						if dom in Ribs[site__][node__]:
							Ribs[site__][node__][dom][prefix]=nexthops
						else:
							Ribs[site__][node__][dom]={prefix:nexthops}
					else:
						Ribs[site__][node__]={dom: {prefix:nexthops} }
		return Ribs
		
	def getIPv4Address(self,site=""):
		
		if site:
			resp=self.sessions[site].get('/api/class/ipv4Addr.json')
			intfs = json.loads(resp.text)['imdata']
			IPv4Address=[ self.parsingDnInt(interf['ipv4Addr']['attributes']['dn']) for interf in intfs ]
			
		else:
			IPv4Address={}
			for site__ in self.sites:
				resp=self.sessions[site__].get('/api/class/ipv4Addr.json')
				intfs = json.loads(resp.text)['imdata']
				IPv4Address[site__]=[  self.parsingDnInt(interf['ipv4Addr']['attributes']['dn']) for interf in intfs ]
			
		return IPv4Address
		
	def getNode(self,site=""):
		
		nodes={}
		if site:
			items=Node.get(self.sessions[site])
			nodes={ item.node: { 'name':item.name , 'info':{ item__:item.__dict__[item__] for item__ in item.__dict__ if item__ !='_session'}  } for item in items } 

			
		else:
			for site__ in self.sites:
				items=Node.get(self.sessions[site__])
				nodes[site__]={ item.node: { 'name':item.name , 'info':{ item__:item.__dict__[item__] for item__ in item.__dict__ if item__ !='_session'} } for item in items }
			
		return nodes
		
	def getNodeBrief(self,site=""):
		nodes={}
		if site:
			resp=self.sessions[site].get('/api/node/class/fabricNode.json?')
			infoNodes=json.loads(resp.text)['imdata']
			
			for info in infoNodes:
				nodes[info['fabricNode']['attributes']['id']]={'role':info['fabricNode']['attributes']['role'],'name':info['fabricNode']['attributes']['name']}
				
		return nodes