import json
import time
import datetime
import random
import string
import urllib
import base64
import org.parosproxy.paros.network.HttpRequestHeader as HttpRequestHeader
import org.parosproxy.paros.network.HttpHeader as HttpHeader
import org.zaproxy.zap.extension.script.ScriptVars as GlobalVariables
import org.parosproxy.paros.network.HttpMessage as HttpMessage
import org.parosproxy.paros.network.HtmlParameter as HtmlParameter
import org.parosproxy.paros.network.HttpSender as HttpSender
import java.net.HttpCookie as HttpCookie
from org.apache.commons.httpclient import URI
from synchronize import make_synchronized
import org.openqa.selenium.By as By
import java.util.concurrent.TimeUnit as TimeUnit
import org.apache.http.client.utils.URLEncodedUtils as URLEncodedUtils
import java.nio.charset.Charset as Charset;
import java.net.URLEncoder as URLEncoder
import java.nio.charset.StandardCharsets as StandardCharsets

#those are global variable names
ACCESS_TOKEN = "access_token";
ACCESS_TOKEN_CREATION_TIMESTAMP="ACCESS_TOKEN_CREATE_TIMESTAMP";
ACCESS_TOKEN_EXPIRY_IN_SECONDS="ACCESS_TOKEN_EXPIRY_IN_SEC";
#here we define the login url, username and password
KEYCLOAK_URL = "https://yourkeycloak.com/auth/realms/appid/protocol/openid-connect/token"
USERNAME = "user";
PASSWORD = "pass";



#msg is the intercepted message
def sendingRequest(msg, initiator, helper):
    msg.getRequestHeader().getURI().toString())
    accessToken = GlobalVariables.getGlobalVar(ACCESS_TOKEN)

    # is there already a token?
    if accessToken is not None:
        if tokenHasExpired(accessToken) == False:
            setAccessTokenInHttpMessage(accessToken, msg);
            return;
    #At this line, the token is invalid and we need a new one
    accessToken = refreshAccessToken(helper);
    setAccessTokenInHttpMessage(accessToken, msg);
    return;

def login(helper):
    #we need to create a new HTTP message (to send the login request)
    requestUri = URI(KEYCLOAK_URL, False);
    msg = HttpMessage();
    #we set the headers, the credentials are submitted as Base64 encoded 'Authorization' header
    requestHeader = HttpRequestHeader(HttpRequestHeader.POST, requestUri, HttpHeader.HTTP10);
    requestHeader.setHeader("content-type", "application/x-www-form-urlencoded");
    requestHeader.setHeader("Authorization", "Basic " + toBase64(USERNAME, PASSWORD))
    #we need to set our request body
    formBody = "grant_type=client_credentials"
    msg.setRequestHeader(requestHeader);
    msg.setRequestBody(formBody);
    #now we send the request
    helper.getHttpSender().sendAndReceive(msg);
    authenticatedJsonResponseObject = json.loads(str(msg.getResponseBody()));
    accessToken = authenticatedJsonResponseObject.get("access_token");
    accessTokenExpiryInSeconds = authenticatedJsonResponseObject.get("expires_in");
    #now we return a dictionary containing the token and expiry time
    return dict({"accessToken": accessToken, "accessTokenExpiryInSeconds": accessTokenExpiryInSeconds})

@make_synchronized
def refreshAccessToken(helper):
    accessToken = GlobalVariables.getGlobalVar(ACCESS_TOKEN);   
    if accessToken is not None and tokenHasExpired(accessToken) == False:
        return accessToken;
    #otherwise, we need to clear the expired token and/or get a new one
    clearAccessTokenFromGlobalVariables();
    accessTokenDict = login(helper);
    #and refill the global variables with the new token
    setAccessTokenInGlobalVariables(accessTokenDict["accessToken"], accessTokenDict["accessTokenExpiryInSeconds"]);
    return accessTokenDict["accessToken"];

def toBase64(username, password):
	return base64.b64encode(username + ":" + password)

def setAccessTokenInHttpMessage(accessToken, msg):
    #the intercepted message is equipped with the Bearer token
    msg.getRequestHeader().setHeader("Authorization", "Bearer " + accessToken);

def clearAccessTokenFromGlobalVariables():
    GlobalVariables.setGlobalVar(ACCESS_TOKEN, None);
    GlobalVariables.setGlobalCustomVar(ACCESS_TOKEN_CREATION_TIMESTAMP, None);   
    GlobalVariables.setGlobalCustomVar(ACCESS_TOKEN_EXPIRY_IN_SECONDS, None);   
  
def setAccessTokenInGlobalVariables(accessToken, expiryInSeconds):
    GlobalVariables.setGlobalVar(ACCESS_TOKEN, str(accessToken));
    #for an easier script, we do not use IAT from the JWT, instead we just set the creatin timestamp to now, we dont care about one or two seconds difference :)
    GlobalVariables.setGlobalCustomVar(ACCESS_TOKEN_CREATION_TIMESTAMP, time.time());   
    GlobalVariables.setGlobalCustomVar(ACCESS_TOKEN_EXPIRY_IN_SECONDS, expiryInSeconds);

def tokenHasExpired(accessToken):
    accessTokenCreationTimestamp = GlobalVariables.getGlobalCustomVar(ACCESS_TOKEN_CREATION_TIMESTAMP);
    currentTime = time.time();
    difference = currentTime - accessTokenCreationTimestamp;  
    accessTokenExpiryInSeconds = GlobalVariables.getGlobalCustomVar(ACCESS_TOKEN_EXPIRY_IN_SECONDS);
    if difference > accessTokenExpiryInSeconds:
        return True;
    return False;


def responseReceived(msg, initiator, helper):
    #we do not need this, but it is useful for debugging
    pass 
