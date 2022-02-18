package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "DETALLE_SOLICITUDES")
public class DetalleSolicitud implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_detalle_solicitudes")
	private Long codDetalleSolicitud;

	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_solicitud")
	private SolicitudVacaciones solicitudVacaciones;
	
	@Column(name = "fec_solicitado")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecDiaSolicitado;

	public Long getCodDetalleSolicitud() {
		return codDetalleSolicitud;
	}

	public void setCodDetalleSolicitud(Long codDetalleSolicitud) {
		this.codDetalleSolicitud = codDetalleSolicitud;
	}

	public SolicitudVacaciones getSolicitudVacaciones() {
		return solicitudVacaciones;
	}

	public void setSolicitudVacaciones(SolicitudVacaciones solicitudVacaciones) {
		this.solicitudVacaciones = solicitudVacaciones;
	}

	public Date getFecDiaSolicitado() {
		return fecDiaSolicitado;
	}

	public void setFecDiaSolicitado(Date fecDiaSolicitado) {
		this.fecDiaSolicitado = fecDiaSolicitado;
	}


}
