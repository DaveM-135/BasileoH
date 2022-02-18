package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotEmpty;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "CAT_TIPO_GASTOS")
public class TipoGasto implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "cod_tipo_gasto")
    private Long codTipoGasto;

    @NotEmpty
    @Column(name = "desc_tipo_gasto")
    private String descTipoGasto;

    @NotEmpty
    @Column(name = "fec_registro")
    @Temporal(TemporalType.TIMESTAMP)
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date fecRegistro;

	public Long getCodTipoGasto() {
		return codTipoGasto;
	}

	public void setCodTipoGasto(Long codTipoGasto) {
		this.codTipoGasto = codTipoGasto;
	}

	public String getDescTipoGasto() {
		return descTipoGasto;
	}

	public void setDescTipoGasto(String descTipoGasto) {
		this.descTipoGasto = descTipoGasto;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}
    
}