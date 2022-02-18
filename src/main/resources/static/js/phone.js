$(document).ready(function() {
	
	$(".telefono").on({
		"keyup": function(event) {
					$(event.target).val(function(index, value) {
						return value.replace(/\D/g, "")
						.replace(/([0-9])([0-9]{2})^/, '^2-^3')
						.replace(/\B(?=(\d{4})+(?!\d)\-?)/g, "-");
					});
		  		},
		"onload": function(event) {
					$(event.target).val(function(index, value) {
						return value.replace(/\D/g, "")
						.replace(/([0-9])([0-9]{2})^/, '^2-^3')
						.replace(/\B(?=(\d{4})+(?!\d)\-?)/g, "-");
					});
		  		}
	});
});