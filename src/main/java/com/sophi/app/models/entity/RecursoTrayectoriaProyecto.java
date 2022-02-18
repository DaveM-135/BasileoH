package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "RECURSOS_TRAYECTORIA_PROYECTOS")
public class RecursoTrayectoriaProyecto implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_trayectoria_proyecto")
	private Long codTrayectoriaProyecto;
	
	@Column(name = "cod_recurso")
	private Long codRecurso;
	
	@Column(name = "desc_proyecto")
	private String descProyecto;
	
	@Column(name = "desc_actividades")
	private String descActividades;
	
	@Column(name = "fec_inicio_participacion")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecInicioParticipacion;
	
	@Column(name = "fec_fin_participacion")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecFinParticipacion;
	
	@Column(name = "desc_cliente")
	private String descCliente;
	
	@OneToMany(mappedBy="recursoTrayectoriaProyecto")
    private List<DetalleConocimientosProyecto> detalleConocimientosProyecto;

	public Long getCodTrayectoriaProyecto() {
		return codTrayectoriaProyecto;
	}

	public void setCodTrayectoriaProyecto(Long codTrayectoriaProyecto) {
		this.codTrayectoriaProyecto = codTrayectoriaProyecto;
	}

	public Long getCodRecurso() {
		return codRecurso;
	}

	public void setCodRecurso(Long codRecurso) {
		this.codRecurso = codRecurso;
	}

	public String getDescProyecto() {
		return descProyecto;
	}

	public void setDescProyecto(String descProyecto) {
		this.descProyecto = descProyecto;
	}

	public String getDescActividades() {
		return descActividades;
	}

	public void setDescActividades(String descActividades) {
		this.descActividades = descActividades;
	}

	public Date getFecInicioParticipacion() {
		return fecInicioParticipacion;
	}

	public void setFecInicioParticipacion(Date fecInicioParticipacion) {
		this.fecInicioParticipacion = fecInicioParticipacion;
	}

	public Date getFecFinParticipacion() {
		return fecFinParticipacion;
	}

	public void setFecFinParticipacion(Date fecFinParticipacion) {
		this.fecFinParticipacion = fecFinParticipacion;
	}

	public String getDescCliente() {
		return descCliente;
	}

	public void setDescCliente(String descCliente) {
		this.descCliente = descCliente;
	}

	public List<DetalleConocimientosProyecto> getDetalleConocimientosProyecto() {
		return detalleConocimientosProyecto;
	}

	public void setDetalleConocimientosProyecto(List<DetalleConocimientosProyecto> detalleConocimientosProyecto) {
		this.detalleConocimientosProyecto = detalleConocimientosProyecto;
	}

	

}
