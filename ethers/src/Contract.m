/**
 *  MIT License
 *
 *  Copyright (c) 2017 Richard Moore <me@ricmoo.com>
 *
 *  Permission is hereby granted, free of charge, to any person obtaining
 *  a copy of this software and associated documentation files (the
 *  "Software"), to deal in the Software without restriction, including
 *  without limitation the rights to use, copy, modify, merge, publish,
 *  distribute, sublicense, and/or sell copies of the Software, and to
 *  permit persons to whom the Software is furnished to do so, subject to
 *  the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 */

#import "Contract.h"

#include "secp256k1.h"
#include "crypto_scrypt.h"
#include "aes.h"
#include "bip32.h"
#include "bip39.h"
#include "curves.h"
#include "ecdsa.h"
#include "secp256k1.h"

#import "Account.h"
#import "RLPSerialization.h"
#import "SecureData.h"
#import "Utilities.h"

#import "RegEx.h"

#pragma mark -
#pragma mark - Contract

static NSData *NullData = nil;

@implementation Parameter

+ (void)initialize {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NullData = [NSData data];
    });
}

- (instancetype)initWithValue: (NSMutableData*)value dynamic:(BOOL)dynamic {
    self = [self init];
    if (self) {
        _value = value;
        _dynamic = dynamic;
    }
    return self;
}

+ (instancetype) parameterWithValue:(NSMutableData*)value dynamic:(BOOL)dynamic {
    return [[Parameter alloc] initWithValue: (NSMutableData*)value dynamic:(BOOL)dynamic];
}

@end

@implementation Coder

@end

@implementation CoderNumber

+ (void)initialize {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NullData = [NSData data];
    });
}

- (instancetype)initWithSize: (int)size isSigned:(BOOL)isSigned {
    self = [self init];
    if (self) {
        _size = size;
        _isSigned = isSigned;
    }
    return self;
}

+ (instancetype)coderNumberWithSize:(int)size isSigned:(BOOL)isSigned {
    
    NSLog(@"coderNumberWithSize %d",size);
    
    return [[CoderNumber alloc] initWithSize: (int)size isSigned:(BOOL)isSigned];
}

- (NSString *_Nonnull)encode:(NSString *_Nonnull)valueInput
{
    /*
     var value = valueInput; // eslint-disable-line
     
     if (typeof value === 'object' && value.toString && (value.toTwos || value.dividedToIntegerBy)) {
     value = value.toString(10).split('.')[0];
     }
     
     if (typeof value === 'string' || typeof value === 'number') {
     value = String(value).split('.')[0];
     }
     
     value = numberToBN(value);
     value = value.toTwos(size * 8).maskn(size * 8);
     if (signed) {
     value = value.fromTwos(size * 8).toTwos(256);
     }
     return value.toArrayLike(Buffer, 'be', 32);

     */
    
    
    BigNumber *bn = [BigNumber bigNumberWithDecimalString:valueInput];
    
    return bn.hexString;
}

- (NSString *_Nonnull)decode:(NSData *_Nonnull)data offset:(int)offset
{
    return nil;
}


@end


@implementation Contract

#pragma mark - Life-Cycle

+ (void)initialize {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NullData = [NSData data];
    });
}

- (instancetype)initWithABI: (NSString*)ABI {
    self = [self init];
    if (self) {
        _ABI = ABI;
    }
    return self;
}

+ (instancetype)contract {
    return [[Contract alloc] init];
}

+ (instancetype)contractWithABI:(NSString*)ABI {
    return [[Contract alloc] initWithABI:ABI];
}

- (unsigned long) alignSize:(unsigned long)size {
    
    return 32 * ceil(size / 32);
}

- (NSString *) encodeParams: (NSArray * _Nullable) inputs withValues: (NSArray * _Nullable) values
{
    int i=0;
    
    NSMutableArray<Parameter *> *parameterParts = [NSMutableArray new];
    
    for (NSString *input in inputs) {
        NSLog(@"encodeParams: input %@",input);
        
        // determine the type
        
        
       // var paramTypePart = new RegExp(/^((u?int|bytes)([0-9]*)|(address|bool|string)|(\[([0-9]*)\]))/);
        
        RegEx *paramTypePart = [RegEx regExWithPattern:@"^((u?int|bytes)([0-9]*)|(address|bool|string)|([([0-9]*)]))"];
        
        
         if ([paramTypePart matchesExactly:@"uint"]) {
            NSLog(@" uint %@ ",input);
                
            NSArray *parts = [input componentsSeparatedByString:@"uint"];
                
            for (NSString *part in parts) {
                NSLog(@" part %@ ",part);
            }
            
            int size = [parts[parts.count-1] intValue];
            
            NSLog(@" size %d ",size);
            
            CoderNumber *coder = [CoderNumber coderNumberWithSize:size/8 isSigned:false];
             
             
            NSString *tmp1 = [coder encode:values[i]];
            NSString *hexEncoded = [tmp1 substringFromIndex:2];
            NSLog(@" hexEncoded %@ ",hexEncoded);
            // Create a buffer
             
            
             NSMutableData *data = [[NSMutableData alloc] initWithLength:2*32];
             char *zeroes = "0000000000000000000000000000000000000000000000000000000000000000";
             [data replaceBytesInRange:NSMakeRange(0, data.length) withBytes:zeroes];
             NSData *hexData = [hexEncoded dataUsingEncoding:NSUTF8StringEncoding];
             unsigned len = [hexData length];
             unsigned char **aBuffer = malloc(len);
             [hexData getBytes:aBuffer length:len];
             [data replaceBytesInRange:NSMakeRange(data.length-len, len) withBytes:aBuffer];
            
             NSString *tmp = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
             NSLog(@" tmp %@ ",tmp);
              
            Parameter *parameterPart = [Parameter parameterWithValue:data dynamic:false];
            
            [parameterParts addObject:parameterPart];
             
         } else if ([paramTypePart matchesExactly:@"int"]) {
             NSLog(@" int %@ ",input);
             
             NSArray *parts = [input componentsSeparatedByString:@"int"];
             
             for (NSString *part in parts) {
                 NSLog(@" part %@ ",part);
             }
             
             int size = [parts[parts.count-1] intValue];
             
             NSLog(@" size %d ",size);
             
             CoderNumber *coder = [CoderNumber coderNumberWithSize:size/8 isSigned:true];
                 
        } else if ([paramTypePart matchesExactly:@"bool"]) {
            
        } else if ([paramTypePart matchesExactly:@"string"]) {
            
        
        } else if ([paramTypePart matchesExactly:@"bytes"]) {
        
        } else if ([paramTypePart matchesExactly:@"address"]) {
            
        
        } else if ([paramTypePart matchesExactly:@"[]"]) {
        
        } else {
            // Invalid type
        }
        i++;
    }
    
    int staticSize = 0;
    int dynamicSize = 0;
    
    // Now pad with 0's as required
    for (Parameter *part in parameterParts) {
        NSLog(@"part.value.length %d",part.value.length);
        
        if (part.dynamic)
        {
            staticSize  += 32;
            dynamicSize += [self alignSize:part.value.length];
            
        } else {
            staticSize += [self alignSize:part.value.length];
        }
        
    }
    NSLog(@"dynamic %d static %d",dynamicSize,staticSize);
    
    int offset = 0;
    int dynamicOffset = staticSize;

    NSMutableData *data = [[NSMutableData alloc] initWithLength:staticSize + dynamicSize];
    
    
    NSString *zeros = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    NSLog(@"data length %d",zeros.length);
    
    
    for (Parameter *part in parameterParts) {
        if (part.dynamic) {
            /*
            uint256Coder.encode(dynamicOffset).copy(data, offset);
            offset += 32;
            
            part.value.copy(data, dynamicOffset);
            dynamicOffset += alignSize(part.value.length)*/;
        } else {
            unsigned len = [part.value length];
            unsigned char * *aBuffer = malloc(len);
            [part.value getBytes:aBuffer length:len];
            [data replaceBytesInRange:NSMakeRange(offset, len) withBytes:aBuffer];
            offset += [self alignSize:len];
        }
        NSLog(@"offset %d",offset);
        
        
    }
    
    // return '0x' + data.toString('hex');
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    NSLog(@"ret %@",ret);
    
    
    return ret;
}

- (NSString *) encodeMethod:(NSString *)name  withTypes:(NSArray *)inputs withValues: (NSArray *)values
{
    
    // Should verify that the method and parameters match the ABI
    
    int i=0;
    NSString *parameters = @"", *tmp;
    for (NSString *input in inputs) {
        NSLog(@"input %d %@ %@",i,input,values[i]);
        tmp = [parameters stringByAppendingString:input] ;
      
        if (i < inputs.count-1)
            parameters = [tmp stringByAppendingString:@","];
        else
            parameters = tmp;
        
        i++;
    }
    
    NSString *signature = [NSString stringWithFormat:@"%@(%@)",name,parameters];
    
    NSLog(@"signature %@ ",signature);

    NSString *signatureEncoded = [
                                  [
                                   [SecureData secureDataWithData:[signature dataUsingEncoding:NSUTF8StringEncoding]
                                    
                                    ] KECCAK256] hexString
                                  ];
    
    NSLog(@"signatureEncoded %@ ",[signatureEncoded substringToIndex:10]);
    

    
    NSString *paramsEncoded = [self encodeParams:inputs withValues:values];

    NSLog(@"paramsEncoded %@ ",paramsEncoded);

    //NSLog(@"signature %@ %@",signature,[[signature KECCAK256] hexString]);

    
    /*
    var signature = method.name + '(' + utils.getKeys(method.inputs, 'type').join(',') + ')';
    var signatureEncoded = '0x' + new Buffer(utils.keccak256(signature), 'hex').slice(0, 4).toString('hex');
    var paramsEncoded = encodeParams(utils.getKeys(method.inputs, 'type'), values).substring(2);
    
    return '' + signatureEncoded + paramsEncoded;
    */
    
//    return [NSString stringWithFormat:@"%@%@",[signatureEncoded substringToIndex:10],[paramsEncoded substringFromIndex:2]];
    return [NSString stringWithFormat:@"%@%@",[signatureEncoded substringToIndex:10],paramsEncoded];
    
}

@end
