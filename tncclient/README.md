# Twisted support for ncclient

This directory will be used to provide twisted support for the ncclient NETCONF Client
library.  Once things are working, the plan is to upstream this to the 'ncclient'
library.  Until then, or if it is not accepted, this will provide support for basic
NETCONF client operations.

## Supported Operations

The initial support is to be able to support all NETCONF operations except for Notitications
in the initial release of this project.  Check the 'TODO and Outstanding Questions List' below
for any caveats or work-to-be-done.

## General Design Notes

- The _request method seems to be the key point of integration.
  - When synchronous, RPC requests will return an RPCReply object with the results (or RPCError).
  - In async mode, RPC requests will return a python Threading Event() object that the caller can
    use to watch/wait for.
  - For 'twisted-mode', this would should be a 'deferred' object.

## TODO and Outstanding Question List

Here is a list of some outstanding questions and TODO items that will need to be looked
into before we are ready for others for upstreaming. As TODO or Outstanding Questions
are completed, they will be moved to the Completed Question list below.
 - When connecting to a host, we need to accept the host key. How is this best done in
   twisted with respect to connecting to our OLT.  You can do a manual SSH connection and
   accept it then, but that is not good in the field.
 - ncclient supports a context manager (with keyword) for the Manager and Lock objects.
   How is this best supported in the twisted architecture:   
 - RPCListener, need to look into how it is used in both sync/async mode.  Is it only related
   to notifications?
 - What about the Manager's RaiseMode capability. Can this be supported as is? How do we best
   tie this in with ErrBacks?
 - Before returning the deferred object, should we associate a callback and an errback to
   handle the first stage of reception? 
 - There is an RPC timeout parameter for synchronous mode. Can this be reused with twisted to
   place a timeout on its request?

### Completed Questions

 - None at this time