$(document).ready(function() {

	$('#undo_redo').multiselect();
	$('#pr').hide();
	$('#thp').hide();
	$('#cp').hide();
	$( "#preventa" ).prop( "checked", true );
  
	$( "#aceptarProyecto" ).click(function() {
		$( "#preventa" ).prop( "disabled", true );
		$('#pr').show('500');
		$('#thp').show('500');
		$('#cp').show('500');
 	});
  
	$( "#cancelarProyecto" ).click(function() {
		$( "#preventa" ).prop( "checked", true );
	});
  
	$("#nombreProyecto").keydown(function(event){
		var codigo = $("#cliente").val();
		codigo = codigo +"-"+$("#areaComercial").val();
		codigo= codigo + "-" +$("#nombreProyecto").val().substring(-1,3);
		$("#codigoProyecto").val(codigo);
	}); 
	
	$( "#cliente" ).click(function() {
		var codigo = $("#cliente").val();
		codigo = codigo +"-"+$("#areaComercial").val();
		codigo= codigo + "-" +$("#nombreProyecto").val().substring(-1,3);
		$("#codigoProyecto").val(codigo);
	});
	
	$( "#areaComercial" ).click(function() {
		var codigo = $("#cliente").val();
		codigo = codigo +"-"+$("#areaComercial").val();
		codigo= codigo + "-" +$("#nombreProyecto").val().substring(-1,3);
		$("#codigoProyecto").val(codigo);
	});
	
	$( "#cliente" ).change(function() {
		cargaAreasComerciales();
	});
	
	cargaAreasComerciales();
  

});

function cargaAreasComerciales(){
	var cliente=$("#cliente").val();
		//alert("cliente "+cliente);
		$.ajax({ 
			url: "/areaComercialCliente/"+cliente,
        	success: function(res){
        		//alert(res);
        		document.getElementById("areaComercial").innerHTML = "";
        		document.getElementById("areaComercial").innerHTML = res;
        	}
    	});
}

var _gaq = _gaq || [];
  _gaq.push(['_setAccount', 'UA-36251023-1']);
  _gaq.push(['_setDomainName', 'jqueryscript.net']);
  _gaq.push(['_trackPageview']);

  (function() {
    var ga = document.createElement('script'); ga.type = 'text/javascript'; ga.async = true;
    ga.src = ('https:' == document.location.protocol ? 'https://ssl' : 'http://www') + '.google-analytics.com/ga.js';
    var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(ga, s);
  })();