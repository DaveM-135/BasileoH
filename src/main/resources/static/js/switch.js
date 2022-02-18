$(document).ready(function() {
	
  	$("#vactivo").click(function() {
  		if($(this).is(":checked")) {
  			$("#result").val(1);
  		}
        else if($(this).is(":not(:checked)")) {
        	$("#result").val(0);
        }
     });
     
     if($("#result").val() == 1){
     	 $("#vactivo").attr("checked", true);
     } else if($("#result").val() == 0){
     	 $("#vactivo").attr("checked", false);
     }
});