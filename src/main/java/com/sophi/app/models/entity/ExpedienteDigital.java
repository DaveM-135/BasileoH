package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "RECURSOS_EXPEDIENTE_DIGITAL")
public class ExpedienteDigital implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_recurso_expediente")
	private Long codRecursoExpediente;
	
	@Lob
	@Column(name = "documento_evidencia", columnDefinition="BLOB")
	private byte[] documentoEvidencia;
	
	@Column(name = "cod_documento")
	private Long codDocumento;
	
	@Column(name = "cod_recurso")
	private Long codRecurso;
	
	@Column(name = "val_aprobado")
	private Long valAprobado;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecRegistro;

	public Long getCodRecursoExpediente() {
		return codRecursoExpediente;
	}

	public void setCodRecursoExpediente(Long codRecursoExpediente) {
		this.codRecursoExpediente = codRecursoExpediente;
	}

	public byte[] getDocumentoEvidencia() {
		return documentoEvidencia;
	}

	public void setDocumentoEvidencia(byte[] documentoEvidencia) {
		this.documentoEvidencia = documentoEvidencia;
	}

	public Long getCodDocumento() {
		return codDocumento;
	}

	public void setCodDocumento(Long codDocumento) {
		this.codDocumento = codDocumento;
	}

	public Long getCodRecurso() {
		return codRecurso;
	}

	public void setCodRecurso(Long codRecurso) {
		this.codRecurso = codRecurso;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public Long getValAprobado() {
		return valAprobado;
	}

	public void setValAprobado(Long valAprobado) {
		this.valAprobado = valAprobado;
	}
	
}
