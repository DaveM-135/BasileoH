package com.sophi.app.models.entity;

public class DetalleRecursoHoras {
	
	private String nombreRecurso;
	private Long link;
	private Double capturadas;
	private Double aprobadas;
	private Double rechazadas;
	
	public DetalleRecursoHoras(String nombreRecurso, Long link, Double capturadas,Double aprobadas, Double rechazadas) {
		super();
		this.nombreRecurso = nombreRecurso;
		this.link = link;
		this.capturadas = capturadas;
		this.aprobadas = aprobadas;
		this.rechazadas = rechazadas;
	}
	

	public DetalleRecursoHoras(String nombreRecurso, Long link, Double rechazadas) {
		super();
		this.nombreRecurso = nombreRecurso;
		this.link = link;
		this.rechazadas = rechazadas;
	}
	
	public DetalleRecursoHoras(Double capturadas, Double aprobadas, Double rechazadas) {
		super();
		this.capturadas = capturadas;
		this.aprobadas = aprobadas;
		this.rechazadas = rechazadas;
	}
	
	public String getNombreRecurso() {
		return nombreRecurso;
	}
	public void setNombreRecurso(String nombreRecurso) {
		this.nombreRecurso = nombreRecurso;
	}
	public Long getLink() {
		return link;
	}
	public void setLink(Long link) {
		this.link = link;
	}
	public Double getCapturadas() {
		return capturadas;
	}
	public void setCapturadas(Double capturadas) {
		this.capturadas = capturadas;
	}
	public Double getAprobadas() {
		return aprobadas;
	}
	public void setAprobadas(Double aprobadas) {
		this.aprobadas = aprobadas;
	}
	public Double getRechazadas() {
		return rechazadas;
	}
	public void setRechazadas(Double rechazadas) {
		this.rechazadas = rechazadas;
	}
	
	
	

}
