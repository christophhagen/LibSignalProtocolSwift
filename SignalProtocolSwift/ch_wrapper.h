//
//  ch_wrapper1.c
//  TestC
//
//  Created by User on 17.09.17.
//  Copyright © 2017 User. All rights reserved.
//
#ifndef CH_WRAPPER_H__
#define CH_WRAPPER_H__

#include "../SignalProtocol/signal_protocol.h"

/**
 Set the callback functions for the context

 @param context The global Signal Protocol context
 @return 0 on success, negative on error
 */
int ch_crypto_provider_set(signal_context *context);

/**
 Provide the locking mechanism for the global context.

 @param global_context The global Signal Context
 @return 0 on success, negative on failure
 */
int ch_locking_functions_set(signal_context *global_context);

/**
 Cleanup when the contet is destroyed
 */
void ch_locking_functions_destroy(void);



#endif /* CH_WRAPPER_H */
