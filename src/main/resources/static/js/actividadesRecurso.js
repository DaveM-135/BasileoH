$(document).ready(function() {
	
	$("#filterProyecto").change(function(){
		cargaActividades();
	});
	
});

function cargaActividades(){
	$("#contenidoTabla").html('<div class="spinner-grow text-muted"></div>');
	var session = $("#authGetName").val();
	var codProyecto = $("#filterProyecto").val();
	var url = "/misActividadesProyecto/" + session + "/" + codProyecto;
	$("#contenidoTabla").load(url);
}




