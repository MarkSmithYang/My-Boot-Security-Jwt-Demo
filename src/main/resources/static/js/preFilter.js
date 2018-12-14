(function () {
  $.ajaxSetup({
    contentType: 'application/json;charset=utf-8',
    dataType: 'json',
    cache: false,
    processData: false,
    beforeSend: function(e,request){
        //对所有GET请求做统一中文编码
        var reg = new RegExp("[\\u4E00-\\u9FFF]+","g");
        if(request.type === 'GET' && reg.test(request.url)){
            request.url = encodeURI(request.url);
       }
       return;
   }
  });
  $(document).ajaxComplete(function (e,request, settings) {
    if(request.responseJSON && request.responseJSON.status === 401)
    {
      window.location.href = '/';
    }
  });
  $(document).ajaxError(function (e, jqXHR, ajaxOptions, thrownError) {
    if(jqXHR.status === 401)
    {
      window.location.href = '/';
    }
  });
  $.ajaxPrefilter(function( options, originalOptions, jqXHR ) {
    var token = sessionStorage.getItem('token');
    jqXHR.setRequestHeader('token', token || '');
  });
})()
