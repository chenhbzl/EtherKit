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

#import <Foundation/Foundation.h>

#import "Transaction.h"


//typedef unsigned long long Nonce;

@interface Parameter : NSObject

+ (nonnull instancetype) parameterWithValue:(NSString*_Nonnull)value dynamic:(BOOL)dynamic ;
@property (nonatomic, strong, nullable) NSMutableData *value;
@property BOOL dynamic;

@end


@interface Coder : NSObject

- (NSString *_Nonnull)encode:(NSString *_Nonnull)valueInput;
- (NSString *_Nonnull)decode:(NSData *_Nonnull)data offset:(int)offset;

@end

@interface CoderNumber : Coder

+ (nonnull instancetype)coderNumberWithSize:(int)size isSigned:(BOOL)isSigned;

@property int size;
@property BOOL isSigned;

@end

@interface Contract : NSObject

+ (nonnull instancetype)contract;
+ (nonnull instancetype)contractWithABI: (NSString * _Nullable) ABI;

@property (nonatomic, strong, nullable) Address *atAddress;
@property (nonatomic, strong, nullable) NSString *ABI; // The JSON representation

- (NSString *_Nonnull) encodeMethod:(NSString *_Nonnull)name  withTypes:(NSArray *_Nullable)inputs withValues: (NSArray *_Nullable)values;


@end
