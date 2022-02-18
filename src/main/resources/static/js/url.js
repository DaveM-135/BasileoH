$(document).ready(function() {
	if($("#cliente_id").val() == ""){
		var URLactual = window.location;
		var URLstring = URLactual.toString();
		var index = URLstring.lastIndexOf('/');
		var URLid = URLstring.substring(index+1);
		
		$("#cliente_id").val(URLid);
	}
});