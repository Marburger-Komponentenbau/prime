#!/usr/bin/env python
#!"X:\System\Program Files\WinPython-32bit-2.7.5.3\python-2.7.5\python.exe"
#!"C:\Program Files\WinPython-32bit-2.7.5.3\python-2.7.5\python.exe"
# -*- coding: utf-8 -*-
"""
Created on Fri Feb 07 16:46:23 2014

@author: cb3fias
"""

import cgi, lockLib, os, base64, boomCryptPemLib, boomDecryptLib
import cgitb
cgitb.enable()

folderName = 'primeKey'
message = "OK"

print "Content-type:text/html"
print 'Access-Control-Allow-Methods: POST, GET, OPTIONS'
print "Access-Control-Allow-Origin: *\r\n"
print ''

class AddressException(Exception): pass
    
def storeKey(address, key, signature, message):
    pathName = os.path.join(folderName, address, signature)
    pathFileNamePem = os.path.join(pathName, 'k.pem')  
    if os.path.exists(pathName):
        if os.path.isfile(pathFileNamePem):
            # TODO Auf Nachrichten pruefen! erst abholen! ...
            # TODO Ausweisen! Sonst kann man den Account entfuehren ...           
            # TODO Nachrichten STOP ...
                     
            oldKeyFileData = key
            
            with open(pathFileNamePem, 'r') as publicfileR:
                oldKeyFileData = publicfileR.read()
    
            #print "| key: " + oldKeyFileData
            oldKeyFileData = oldKeyFileData.replace("_", "+");
            #print "| key: " + oldKeyFileData
            
            oldKeyData = base64.decodestring(oldKeyFileData)
            oldKey = boomCryptPemLib.PublicKey.load_pkcs1_openssl_der(oldKeyData)  

            #print "| e: " + str(oldKey.e)
            #print "| n: " + str(oldKey.n)   
            
            clear = boomDecryptLib.verify2(signature, oldKey)       
            if clear != message:
                raise AddressException( 'signature not validated...' )            
 
    else:
        try:
            os.makedirs(pathName)
            #print os.path.join('prime', address)
            os.makedirs( os.path.join('prime', address) )
            #print '... geht doch'
        except OSError:
            raise        

    with lockLib.FileLock(address) as lock:
        with open(pathFileNamePem, "w") as file:
            file.write( key )

try:

    arguments = cgi.FieldStorage()
    if arguments.has_key('k'):
        
        key = arguments['k'].value
        
        if arguments.has_key('a'):

            address = arguments['a'].value
            
            if arguments.has_key('s'):
    
                signature = arguments['s'].value

                if arguments.has_key('m'):
        
                    message = arguments['m'].value
                    storeKey(address, key, signature, message)
                    
                else:
                    message = 'missing message'
                
            else:
                message = 'missing signature' 
            
        else:
            message = 'missing address'        
        
    else:
        message = 'missing key'
    
except AddressException, e:    
    message = 'address exception: ' + e.message
except lockLib.LockException, e:    
    message = 'lock exception: ' + e.message    
except Exception, e:    
    message = 'unknown exception: ' + e.message 
except:   
    message = 'Fatal unknown Error'

print message
    
