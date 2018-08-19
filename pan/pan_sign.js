if(process.argv[2] == 'debug'){
  console.log('sign=80gXOpRcTzvxVjNPBQmT8FMoqzOlbDvWeUK%2BiZZVsn4xFMSnf3yHhg%3D%3D&timestamp=1399694676');
  process.exit(0);
}

var HttpClient = require('handy-http');
var qs = require('querystring');
var util = require('util');

var client = new HttpClient();
client.open({
  url: 'http://pan.baidu.com/disk/home',
  headers: {
    'Cookie': process.argv[2] || 'BDUSS=UdwcTVBOWRHQXZneTdVc1N4N0tZY3QyQXZERXBDVndDMEFEcjNoaDdWeUNVbHBUQVFBQUFBJCQAAAAAAAAAAAEAAAAggFYLTGVlWGlhb2xhbgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAILFMlOCxTJTN',
  },
}, function(err, res){
  if(err){
    console.error(err);
    process.exit(1);
  }
  var content = res.toString('utf8');
  getSign(content);
});

/*
<script type="text/javascript">FileUtils.third="0";FileUtils.taskTime="1399690830";FileUtils.taskKey="2d7571d71c134bec1a5ab475dda13567ab6edf5c";FileUtils.bt_paths="";FileUtils.timeLineGuideState="1";FileUtils.timeLineStatus=true;FileUtils.sign1="6859b22429bf7f3bf9d976bac019cd8ded682a1c";FileUtils.sign2=function s(j,r){var a=[];var p=[];var o="";var v=j.length;for(var q=0;q<256;q++){a[q]=j.substr((q%v),1).charCodeAt(0);p[q]=q}for(var u=q=0;q<256;q++){u=(u+p[q]+a[q])%256;var t=p[q];p[q]=p[u];p[u]=t}for(var i=u=q=0;q<r.length;q++){i=(i+1)%256;u=(u+p[i])%256;var t=p[i];p[i]=p[u];p[u]=t;k=p[((p[i]+p[u])%256)];o+=String.fromCharCode(r.charCodeAt(q)^k)}return o};;FileUtils.sign3="e8c7d729eea7b54551aa594f942decbe";FileUtils.timestamp="1399690830";</script>
*/
/*
2014-06-19 invalid.
function getSign(content){
  var re = /<script type="text\/javascript">(.+?FileUtils\.sign1.+?)<\/script>/;
  var m = content.match(re);
  if(!m){
    console.error('Can not find snippet.');
    process.exit(2);
  }
  evalSign(m[1]);
}

function evalSign(snippet){
  var FileUtils = Object();
  eval(snippet);
  var sign = base64Encode(FileUtils.sign2(FileUtils.sign3, FileUtils.sign1));
  var data = util.format('sign=%s&timestamp=%s', qs.escape(sign), FileUtils.timestamp);
  console.log(data);
}
*/

function base64Encode(G){var C="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",B,A,_,F,D,E;_=G.length;A=0;B="";while(A<_){F=G.charCodeAt(A++)&255;if(A==_){B+=C.charAt(F>>2);B+=C.charAt((F&3)<<4);B+="==";break;}D=G.charCodeAt(A++);if(A==_){B+=C.charAt(F>>2);B+=C.charAt(((F&3)<<4)|((D&240)>>4));B+=C.charAt((D&15)<<2);B+="=";break;}E=G.charCodeAt(A++);B+=C.charAt(F>>2);B+=C.charAt(((F&3)<<4)|((D&240)>>4));B+=C.charAt(((D&15)<<2)|((E&192)>>6));B+=C.charAt(E&63);}return B;}

/*
!function() {
    yunData.ISFIRST = "";
    yunData.UINFO = null;
    yunData.task_key = 'a1d961d80995c488e4ec10bac2ebf45e05e08dcf';
    yunData.task_time = '1403187141';
    yunData.sign1 = 'ea2e8c721a5b8c27459a74d284d44538f8543425';
    yunData.sign2 = 'function s(j,r){var a=[];var p=[];var o=\x22\x22;var v=j.length;for(var q=0;q<256;q++){a[q]=j.substr((q%v),1).charCodeAt(0);p[q]=q}for(var u=q=0;q<256;q++){u=(u+p[q]+a[q])%256;var t=p[q];p[q]=p[u];p[u]=t}for(var i=u=q=0;q<r.length;q++){i=(i+1)%256;u=(u+p[i])%256;var t=p[i];p[i]=p[u];p[u]=t;k=p[((p[i]+p[u])%256)];o+=String.fromCharCode(r.charCodeAt(q)^k)}return o};';
    yunData.sign3 = 'd76e889b6aafd3087ac3bd56f4d4053a';
    yunData.timestamp = '1403187141';
}();
*/
function getSign(content){
  var re = /<script type="text\/javascript">(.+?FileUtils\.sign1.+?)<\/script>/;
  var re = /(yunData\.sign1((.|\r|\n)+)yunData.timestamp[^;]+;)/;
  var m = content.match(re);
  if(!m){
    console.error('Can not find snippet.');
    process.exit(2);
  }
  evalSign(m[1]);
}

function evalSign(snippet){
  var yunData = Object();
  eval(snippet);
  if("function" != typeof yunData.sign2){
    try{
      yunData.sign2 = new Function("return " + yunData.sign2)();
    }catch(a){
    }
  }
  var FileUtils = yunData;
  var sign = base64Encode(FileUtils.sign2(FileUtils.sign3, FileUtils.sign1));
  var data = util.format('sign=%s&timestamp=%s', qs.escape(sign), FileUtils.timestamp);
  console.log(data);
}
