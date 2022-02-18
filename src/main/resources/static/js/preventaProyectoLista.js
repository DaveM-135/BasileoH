$(document).ready(function() {

	//cargaTodos();

	$( "#cliente" ).change(function() {
		var cliente=$("#cliente").val();
		//alert("cliente "+cliente);
		$.ajax({ 
					url: "/cargaProyectosTodo/"+cliente,
        			success: function(res){
        				//alert(res);
        				
        				document.getElementById("contenidoTabla").innerHTML = "";
        				document.getElementById("contenidoTabla").innerHTML = res;
        				 $('#dataTable').DataTable();
        				 //alert("llega hasta aca");
        			}
    	});
	});
});

function cargaTodos() {
  $.ajax({ 
					url: "/cargaProyectosTodo/-1",
        			success: function(res){
        				//alert(res);
        				
        				document.getElementById("contenidoTabla").innerHTML = "";
        				document.getElementById("contenidoTabla").innerHTML = res;
        				$('#dataTable').DataTable();
        				//alert("llega hasta aca");
        			}
    	});
}