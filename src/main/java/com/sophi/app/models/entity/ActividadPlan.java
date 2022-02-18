package com.sophi.app.models.entity;

import com.opencsv.bean.CsvBindByPosition;

public class ActividadPlan {
	
	@CsvBindByPosition(position = 0)
	private String numActividad;
	
	@CsvBindByPosition(position = 1)
	private String edt;
	
	@CsvBindByPosition(position = 2)
	private String nombre;
	
	@CsvBindByPosition(position = 3)
	private String duracion;
	
	@CsvBindByPosition(position = 4)
	private String esfuerzo;
	
	@CsvBindByPosition(position = 5)
	private String porcentajeCompletado;
		
	@CsvBindByPosition(position = 6)
	private String inicio;
	
	@CsvBindByPosition(position = 7)
	private String fin;
	
	@CsvBindByPosition(position = 8)
	private String predecesora;
	
	@CsvBindByPosition(position = 9)
	private String recursos;
	
	private int serie; 
	
	public int getSerie() {
		return serie;
	}

	public void setSerie(int serie) {
		this.serie = serie;
	}

	public ActividadPlan() {
		
	}

	public ActividadPlan(String numActividad, String edt, String nombre, String duracion, String esfuerzo,
			String porcentajeCompletado, String inicio, String fin, String predecesora, String recursos) {
		super();
		this.numActividad = numActividad;
		this.edt = edt;
		this.nombre = nombre;
		this.duracion = duracion;
		this.esfuerzo = esfuerzo;
		this.porcentajeCompletado = porcentajeCompletado;
		this.inicio = inicio;
		this.fin = fin;
		this.predecesora = predecesora;
		this.recursos = recursos;
	}

	public String getNumActividad() {
		return numActividad;
	}

	public void setNumActividad(String numActividad) {
		this.numActividad = numActividad;
	}

	public String getNombre() {
		return nombre;
	}

	public void setNombre(String nombre) {
		this.nombre = nombre;
	}

	public String getEdt() {
		return edt;
	}

	public void setEdt(String edt) {
		this.edt = edt;
	}

	public String getDuracion() {
		return duracion;
	}

	public void setDuracion(String duracion) {
		this.duracion = duracion;
	}

	public String getEsfuerzo() {
		return esfuerzo;
	}

	public void setEsfuerzo(String esfuerzo) {
		this.esfuerzo = esfuerzo;
	}

	public String getPorcentajeCompletado() {
		return porcentajeCompletado;
	}

	public void setPorcentajeCompletado(String porcentajeCompletado) {
		this.porcentajeCompletado = porcentajeCompletado;
	}

	public String getInicio() {
		return inicio;
	}

	public void setInicio(String inicio) {
		this.inicio = inicio;
	}

	public String getFin() {
		return fin;
	}

	public void setFin(String fin) {
		this.fin = fin;
	}

	public String getPredecesora() {
		return predecesora;
	}

	public void setPredecesora(String predecesora) {
		this.predecesora = predecesora;
	}

	public String getRecursos() {
		return recursos;
	}

	public void setRecursos(String recursos) {
		this.recursos = recursos;
	};

	
	
//	Encabezado del archivo CSV
//	 ID,Nombre,Duración,Esfuerzo,% Completado,Inicio,Fin,Predecesoras,Recursos,
	
	


}
