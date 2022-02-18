$(document).ready(function(){
	if($("#tipoFacturacion").val() == 3){
		$("#pp").hide();
	}
		
	else{
		$("#pp").show();
	}

	$("#tipoFacturacion").change(function(){
		if($("#tipoFacturacion").val() == 3){
			$("#pp").hide();
		}
		
		else{
			$("#pp").show();
		}
	});
});