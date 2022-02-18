$(document).ready(function() {
	
	$("#presupuesto").on({
		"focus": function(event) {
					$(event.target).select();
				},
		"keyup": function(event) {
					$(event.target).val(function(index, value) {
						return value.replace(/\D/g, "")
						.replace(/([0-9])([0-9]{2})$/, '$1.$2')
						.replace(/\B(?=(\d{3})+(?!\d)\.?)/g, ",");
					});
		  		}
	});

	$('#undo_redo').multiselect();
	$('#pr').hide();
	$('#thp').hide();
	$('#cp').hide();
	$('#pp').hide();
	$('#thv').hide();
	$('#fi').hide();
	$('#ff').hide();
	$( "#preventa" ).prop( "checked", true );
  
	$( "#aceptarProyecto" ).click(function() {
		$( "#preventa" ).prop( "disabled", true );
		$('#pr').show('500');
		$('#thp').show('500');
		$('#cp').show('500');
		$('#pp').show('500');
		$('#thv').show('500');
		$('#ff').show('500');
		$('#fi').show('500');
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
	
//	$( "#areaComercial" ).click(function() {
//		var codigo = $("#cliente").val();
//		codigo = codigo +"-"+$("#areaComercial").val();
//		codigo= codigo + "-" +$("#nombreProyecto").val().substring(-1,3);
//		$("#codigoProyecto").val(codigo);
//	});
	
});