package com.sophi.app.models.entity;

public class LiderProyectoEvaluacion {
	
	private Long codRecursoLider;
	private Long codProyecto; 
	private String descProyecto;
	private String nombreRecursoLider;
	private String mailRecursoLider;
	
	public LiderProyectoEvaluacion(Long codRecursoLider) {
		super();
		this.codRecursoLider = codRecursoLider;
	}
	
	public LiderProyectoEvaluacion() {
		
	}
	
	public Long getCodRecursoLider() {
		return codRecursoLider;
	}
	public void setCodRecursoLider(Long codRecursoLider) {
		this.codRecursoLider = codRecursoLider;
	}
	public Long getCodProyecto() {
		return codProyecto;
	}
	public void setCodProyecto(Long codProyecto) {
		this.codProyecto = codProyecto;
	}
	public String getDescProyecto() {
		return descProyecto;
	}
	public void setDescProyecto(String descProyecto) {
		this.descProyecto = descProyecto;
	}
	public String getNombreRecursoLider() {
		return nombreRecursoLider;
	}
	public void setNombreRecursoLider(String nombreRecursoLider) {
		this.nombreRecursoLider = nombreRecursoLider;
	}
	public String getMailRecursoLider() {
		return mailRecursoLider;
	}
	public void setMailRecursoLider(String mailRecursoLider) {
		this.mailRecursoLider = mailRecursoLider;
	}
	
	

}
