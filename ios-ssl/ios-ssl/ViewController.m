//
//  ViewController.m
//  ios-ssl
//
//  Created by wzj on 2019/1/18.
//  Copyright © 2019年 wzj. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSString *path = [[NSBundle mainBundle] pathForResource:@"my" ofType:@"crt"];
    NSLog(@"path = %@", path);
    NSData* crtData = [NSData dataWithContentsOfFile:path];
    
    //NSMutableArray *policies = [NSMutableArray array];
    // BasicX509 不验证域名是否相同
    //SecPolicyRef policy = SecPolicyCreateBasicX509();
    //[policies addObject:(__bridge_transfer id)policy];
    //SecTrustSetPolicies(trust, (__bridge CFArrayRef)policies);
    
    
//        NSURL *url = [NSURL URLWithString:@"https://cn-n1-jetty3.ecamzone.cc/eques/404.html"];
//        //block方式
//        NSURLSession * session = [NSURLSession sharedSession];
//        NSURLSessionDataTask * task = [session dataTaskWithURL:url completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
//            //[NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableLeaves error:nil];
//        }];
//
//        [task resume];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]
                                                          delegate:self delegateQueue:[NSOperationQueue mainQueue]];

    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://cn-n1-jetty1.ecamzone.cc/eques/404.html"]
                                        completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
                                            NSLog(@"[completionHandler] %@", [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
                                        }];
    [task resume];
   
//    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://cn-n1-jetty3.ecamzone.cc/eques/404.html"]];
//
//    // Create url connection and fire request
//    NSURLConnection *conn = [[NSURLConnection alloc] initWithRequest:request delegate:self];
//
    
}

OSStatus extractIdentityAndTrust(CFDataRef inP12data, SecIdentityRef *identity, SecTrustRef *trust)
{
    OSStatus securityError = errSecSuccess;
    
    CFStringRef password = CFSTR("userA");
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { password };
    
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inP12data, options, &items);
    
    if (securityError == 0) {
        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemIdentity);
        *identity = (SecIdentityRef)tempIdentity;
        const void *tempTrust = NULL;
        tempTrust = CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemTrust);
        *trust = (SecTrustRef)tempTrust;
    }
    
    if (options) {
        CFRelease(options);
    }
    
    return securityError;
}


- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler
{
    NSLog(@"didReceiveChallenge ");
    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    SecCertificateRef certificate  = SecTrustGetCertificateAtIndex(serverTrust, 0);
    NSData* remoteCertificateData = CFBridgingRelease(CFBridgingRetain(CFBridgingRelease(SecCertificateCopyData(certificate))));
    NSString* string = @"MIIDGjCCAgICCQCLqNNfMWgBFjANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJY"\
    "WDELMAkGA1UECgwCWFgxCzAJBgNVBAsMAlhYMQswCQYDVQQLDAJYWDELMAkGA1UE"\
    "CwwCWFgxCzAJBgNVBAMMAlhYMCAXDTE5MDExODAzMzQwMFoYDzIxMTgxMjI1MDMz"\
    "NDAwWjBOMQswCQYDVQQGEwJYWDELMAkGA1UECgwCWFgxCzAJBgNVBAsMAlhYMQsw"\
    "CQYDVQQLDAJYWDELMAkGA1UECwwCWFgxCzAJBgNVBAMMAlhYMIIBIjANBgkqhkiG"\
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0aY79Jc3CEu8tiJqkYd4XDa0iMdJouwp2KW9"\
    "kfaxKChhvYa2znFyyt/Rf7v3w/y/ogLYDLBxrdiO5Lf3Uzqx3Nl9hrVxxzPKlcWd"\
    "JJxx/g7A6bVkZfAXALYZMWTwzPLc1qhhACJ1nTU4TVZ7mBPvo+5Svhn0Wie0mnw+"\
    "1EU7Asxhzt6tX68XiaT67Of4Ld2Nl+xT27zV4Lm/qLVHSLeuQ49vAG2xOWUQUyd9"\
    "ecGSbrDP0Z/se+etx+m4JhXPEAd+MJ+35dxfj3VzRK+OaanZ4dkucqVTe6U9pxyR"\
    "pi9l4mXVf8olT5PxtyMLKIhvGx2aFfv7ihPaZFIZnS/gO0VSswIDAQABMA0GCSqG"\
    "SIb3DQEBCwUAA4IBAQBA2wqn/kJzsCYqLBrAfgXwmd9ZexEpzKgyNq0Vwqe4lWiL"\
    "66VAChaJhBurBUbk3D5XxysMm7bz/T7W/IGIML2v+PLDQonZU6Ye0LAYSPxVwAbJ"\
    "z0YlDVThY9vV71K/sAc83K4lN5jtFBBDO+ZbsUELpS0o2u7HZHtV8g20RhApt/Im"\
    "2bwylurzohDi6RA+U059VBmo9IeSxb54lZ+ohGDyF2fXVjfzo5aBqVfyyW2xC6Ld"\
    "I1PDGmu4OwvkBdOdvwvVT583fifrDuv2CzqT3KSdIkSf50BbiTyBO434nZ2OPDy6"\
    "tTZAU/BHGzQrq+/qHpzFZ5+AI9sHLQTpRMOeHAge";
    NSData *localCertificateData = [[NSData alloc]initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    NSLog(@"remote %@",remoteCertificateData);
    NSLog(@"local %@", localCertificateData);
    if ([remoteCertificateData isEqualToData:localCertificateData ]) {
        NSLog(@"equal");
        NSURLCredential* credential = [NSURLCredential credentialForTrust:serverTrust];
        [challenge.sender useCredential:credential forAuthenticationChallenge: challenge];
         completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    } else {
        NSLog(@"not equal");
        completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
    }
    
    
//    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
//        NSLog(@"server ---------");

//        NSString *host = challenge.protectionSpace.host;
//        NSLog(@"%@", host);
//        NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
//        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
//
//
//        path = Directory.GetParent(GlobaleObjekte.SSLZertifikatePath);
//        var caPath = Path.Combine(path.FullName, "ca.cert.der");
//        var caByteArray = File.ReadAllBytes(caPath);
//        var caCert = new SecCertificate(caByteArray);
//
//        var interPath = Path.Combine(path.FullName, "intermediate.cert.der");
//        var interByteArray = File.ReadAllBytes(interPath);
//        var interCert = new SecCertificate(interByteArray);
//
//        clientPath = Path.Combine(path.FullName, "client.pfx");
//        clientByteArray = File.ReadAllBytes(clientPath);
//        clientCert = X509Certificate2(clientByteArray, Settings.WSClientCertPasswort);
//
//        var identity = SecIdentity.Import(clientCert);
//        credential = new NSUrlCredential(identity, new SecCertificate[] { caCert, interCert }, NSUrlCredentialPersistence.ForSession);
//
//        completionHandler(NSUrlSessionAuthChallengeDisposition.UseCredential, credential);
//
        
//    }
//    else if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate])
//    {
        //客户端证书认证
        //TODO:设置客户端证书认证
        // load cert
//        NSLog(@"client");
//        NSString *path = [[NSBundle mainBundle]pathForResource:@"my" ofType:@"crt"];
//        NSLog(@"crt path: %@", path);
//        NSData *p12data = [NSData dataWithContentsOfFile:path];
//        CFDataRef inP12data = (__bridge CFDataRef)p12data;
//        SecIdentityRef myIdentity;
//        OSStatus status = [self extractIdentity:inP12data toIdentity:&myIdentity];
//        if (status != 0) {
//            return;
//        }
//        SecCertificateRef myCertificate;
//        SecIdentityCopyCertificate(myIdentity, &myCertificate);
//        const void *certs[] = { myCertificate };
//        CFArrayRef certsArray =CFArrayCreate(NULL, certs,1,NULL);
//        NSURLCredential *credential = [NSURLCredential credentialWithIdentity:myIdentity certificates:(__bridge NSArray*)certsArray persistence:NSURLCredentialPersistencePermanent];
//        //        [[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];
//        //         网上很多错误代码如上，正确的为：
//        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    //}
}

- (OSStatus)extractIdentity:(CFDataRef)inP12Data toIdentity:(SecIdentityRef*)identity {
    NSLog(@"extractIdentity");
    OSStatus securityError = errSecSuccess;
    CFStringRef password = CFSTR("123456");
    const void *keys[] = { kSecImportExportPassphrase};
    const void *values[] = { password };
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inP12Data, options, &items);
    if (securityError == 0)
    {
        NSLog(@"import crt ok, %ld", CFArrayGetCount(items));
        CFDictionaryRef ident = CFArrayGetValueAtIndex(items,0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue(ident, kSecImportItemIdentity);
        *identity = (SecIdentityRef)tempIdentity;
    }
    else
    {
        NSLog(@"clinet.p12 error!");
    }
    
    if (options) {
        CFRelease(options);
    }
    return securityError;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
    // A response has been received, this is where we initialize the instance var you created
    // so that we can append data to it in the didReceiveData method
    // Furthermore, this method is called each time there is a redirect so reinitializing it
    // also serves to clear it
    _responseData = [[NSMutableData alloc] init];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
    // Append the new data to the instance variable you declared
    [_responseData appendData:data];
}

- (NSCachedURLResponse *)connection:(NSURLConnection *)connection
                  willCacheResponse:(NSCachedURLResponse*)cachedResponse {
    // Return nil to indicate not necessary to store a cached response for this connection
    return nil;
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    // The request is complete and data has been received
    // You can parse the stuff in your instance variable now
    
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    // The request has failed for some reason!
    // Check the error var
}


@end
