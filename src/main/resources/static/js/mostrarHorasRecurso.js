$(document).ready(function() {
	var tabla = $('#dataTable');
	var codProyecto = $('.codProyecto');
	var fila = $('tr');
	var filtro = $('#filterProyecto');
	
	for(var i=1 ; i<fila.length ; i++){
		fila.eq(i).attr('id', codProyecto.eq(i-1).val());
	}
	
	$("#filterProyecto").change(function() {
		var valor = $(this).val();
		if(valor != -1){
			$('tr:not(#' + valor + ')', tabla).hide();
			$('tr', tabla).eq(0).show();
			$('tr#' + valor, tabla).show();
		}
			
		else{
			$('tr', tabla).show();
		}
	});
});