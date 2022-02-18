$(document).ready(function() {
	var tabla = $('#dataTable');
	var codProyecto = $('.codProyecto');
	var fila = $('tr');
	var filtro = $('#filterProyecto');
	
	for(var i=1 ; i<fila.length ; i++){
		fila.eq(i).attr('id', codProyecto.eq(i-1).val());
	}
	
	$("#filterProyecto").change(function() {
		cargaInfoFiltro();
//		var valor = $(this).val();
//		if(valor != -1){
//			$('tr:not(#' + valor + ')', tabla).hide();
//			$('tr', tabla).eq(0).show();
//			$('tr#' + valor, tabla).show();
//		}
//			
//		else{
//			$('tr', tabla).show();
//		}
	});
});

function cargaInfoFiltro(){
	$("#contenidoTabla").html('<div class="spinner-grow text-muted"></div>');
	var codProyecto = "";
	if ($("#filterProyecto").val() == "-1"){
		$("#filterProyecto option").each(function(){
			codProyecto +=$(this).val() + "," ;
		});
	} else {
		codProyecto = $("#filterProyecto").val();
	}
	
	var url = "/aprobacionGastosProyecto/" + codProyecto;
	console.log(codProyecto);
	$("#contenidoTabla").load(url);
}

function verComprobante(codGasto){
	$("#imgComprobante").removeAttr('src');
	url="/imagenComprobante/"+codGasto;	
	$("#imgComprobante").attr('src',url);
}