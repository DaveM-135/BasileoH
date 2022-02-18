package com.sophi.app.models.entity;

public class ResumenForecastGeneral {
	
	private String nombreMes;
	
	private MesHabil mesHabil;
	
	private Long totalHorasHabiles;

	public String getNombreMes() {
		return nombreMes;
	}

	public void setNombreMes(String nombreMes) {
		this.nombreMes = nombreMes;
	}

	public MesHabil getMesHabil() {
		return mesHabil;
	}

	public void setMesHabil(MesHabil mesHabil) {
		this.mesHabil = mesHabil;
	}

	public Long getTotalHorasHabiles() {
		return totalHorasHabiles;
	}

	public void setTotalHorasHabiles(Long totalHorasHabiles) {
		this.totalHorasHabiles = totalHorasHabiles;
	}
	
	

}
