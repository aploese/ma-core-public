//>>built
define("xstyle/core/observe",[],function(){function q(a,c,b){f?-1===f.indexOf(a)&&f.push(a):(f=[a],setTimeout(function(){f.forEach(function(a){var b=[];a.properties.forEach(function(c){b.push({target:a.object,name:c})});a(b);a.object=null;a.properties=null});f=null},0));a.object=c;a=a.properties||(a.properties=[]);-1===a.indexOf(b)&&a.push(b)}var l=Object.observe,m;if(m=Object.defineProperty)a:{try{Object.defineProperty({},"t",{});m=!0;break a}catch(t){}m=void 0}var l={observe:l,defineProperty:m},
f,h=[],p=[],n=[],r=!1;return{observe:l.observe?Object.observe:l.defineProperty?function(a,c){c.addKey=function(b){var d="key"+b;if(!this[d]){this[d]=!0;var g=a[b];if((d=Object.getOwnPropertyDescriptor(a,b))&&d.set){var f=d.set,s=d.get;Object.defineProperty(a,b,{get:function(){return g=s.call(this)},set:function(a){f.call(this,a);g!==a&&(g=a,c&&q(c,this,b))}})}else Object.defineProperty(a,b,{get:function(){return g},set:function(a){g!==a&&(g=a,c&&q(c,this,b))}})}};c.remove=function(){c=null}}:function(a,
c){r||(r=!0,setInterval(function(){for(var a=0,b=h.length;a<b;a++){var c=p[a],d=h[a],f=n[a],k=void 0,e=void 0;for(e in c)c.hasOwnProperty(e)&&c[e]!==d[e]&&(c[e]=d[e],(k||(k=[])).push({name:e}));for(e in d)d.hasOwnProperty(e)&&!c.hasOwnProperty(e)&&(c[e]=d[e],(k||(k=[])).push({name:e}));k&&f(k)}},20));var b={},d;for(d in a)a.hasOwnProperty(d)&&(b[d]=a[d]);h.push(a);p.push(b);n.push(c)},unobserve:l.observe?Object.unobserve:function(a,c){c.remove&&c.remove();for(var b=0,d=h.length;b<d;b++)if(h[b]===
a&&n[b]===c){h.splice(b,1);p.splice(b,1);n.splice(b,1);break}}}});
//# sourceMappingURL=observe.js.map