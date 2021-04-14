#!/bin/python3.7
# coding: utf-8

import sys
import argparse
import pdb
import yaml
import os
from time import gmtime, strftime , localtime

from  aci.Fabric import *

from acitoolkit.acitoolkit import Session
from acitoolkit.aciphysobject import Node
from acitoolkit.acitoolkit import *
import pwd 

import json
from pprint import pprint as ppr

sys.path.insert(0,'/home/x112097/py3')
from getHosts import *
from getsec import *

def getAllFabric():
	return [ fabric for fabric in hash_of_conf_files.keys() ]

if __name__ == '__main__':
	"Fonction principale"
	parser = argparse.ArgumentParser()
	
	parser.add_argument('--list-site',dest='list_site',help='display all known fabric')
	
	if args.'list_site':
		ppr(getAllFabric())


