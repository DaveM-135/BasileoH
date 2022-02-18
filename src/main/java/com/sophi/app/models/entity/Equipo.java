package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_EQUIPO")
public class Equipo implements Serializable{

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_herramienta")
	private Long codHerramienta;
	
	@Column(name = "desc_herramienta")
	private String descHerramienta;
	
	@Column(name = "desc_modelo")
	private String descModelo;
	
	@Column(name = "desc_num_serie")
	private String descNumSerie;
	
	@Column(name = "cod_tipo_herramienta")
	private Long codTipoHerramienta;
	
	@Column(name = "cod_estado_herramienta")
	private Long codEstadoHerramienta;
	
	@OneToOne
	@JoinColumn(name = "cod_tipo_herramienta", insertable=false, updatable=false)
	private TipoHerramienta tipoHerramienta;
	
	@OneToOne
	@JoinColumn(name = "cod_estado_herramienta", insertable=false, updatable=false)
	private EstadoHerramienta estadoHerramienta;
	
	@Column(name = "desc_sistema_operativo")
	private String descSistemaOperativo;
	
	@Column(name = "desc_procesador")
	private String descProcesador;
	
	@Column(name = "desc_memoria")
	private String descMemoria;
	
	@Column(name = "desc_almacenamiento")
	private String descAlmacenamiento;
	
	@Column(name = "desc_marca")
	private String descMarca;
	
	@Column(name = "desc_modelo_version")
	private String descModeloVersion;
	
	@Column(name = "val_propio")
	private Long valPropio;
	
	@Column(name = "ano_adquisicion")
	private Long anoAdquisicion;
	
	public Long getCodHerramienta() {
		return codHerramienta;
	}

	public void setCodHerramienta(Long codHerramienta) {
		this.codHerramienta = codHerramienta;
	}

	public String getDescHerramienta() {
		return descHerramienta;
	}

	public void setDescHerramienta(String descHerramienta) {
		this.descHerramienta = descHerramienta;
	}

	public String getDescModelo() {
		return descModelo;
	}

	public void setDescModelo(String descModelo) {
		this.descModelo = descModelo;
	}

	public String getDescNumSerie() {
		return descNumSerie;
	}

	public void setDescNumSerie(String descNumSerie) {
		this.descNumSerie = descNumSerie;
	}

	public Long getCodTipoHerramienta() {
		return codTipoHerramienta;
	}

	public void setCodTipoHerramienta(Long codTipoHerramienta) {
		this.codTipoHerramienta = codTipoHerramienta;
	}

	public Long getCodEstadoHerramienta() {
		return codEstadoHerramienta;
	}

	public void setCodEstadoHerramienta(Long codEstadoHerramienta) {
		this.codEstadoHerramienta = codEstadoHerramienta;
	}

	public TipoHerramienta getTipoHerramienta() {
		return tipoHerramienta;
	}

	public void setTipoHerramienta(TipoHerramienta tipoHerramienta) {
		this.tipoHerramienta = tipoHerramienta;
	}

	public EstadoHerramienta getEstadoHerramienta() {
		return estadoHerramienta;
	}

	public void setEstadoHerramienta(EstadoHerramienta estadoHerramienta) {
		this.estadoHerramienta = estadoHerramienta;
	}

	public String getDescSistemaOperativo() {
		return descSistemaOperativo;
	}

	public void setDescSistemaOperativo(String descSistemaOperativo) {
		this.descSistemaOperativo = descSistemaOperativo;
	}

	public String getDescProcesador() {
		return descProcesador;
	}

	public void setDescProcesador(String descProcesador) {
		this.descProcesador = descProcesador;
	}

	public String getDescMemoria() {
		return descMemoria;
	}

	public void setDescMemoria(String descMemoria) {
		this.descMemoria = descMemoria;
	}

	public String getDescAlmacenamiento() {
		return descAlmacenamiento;
	}

	public void setDescAlmacenamiento(String descAlmacenamiento) {
		this.descAlmacenamiento = descAlmacenamiento;
	}

	public String getDescMarca() {
		return descMarca;
	}

	public void setDescMarca(String descMarca) {
		this.descMarca = descMarca;
	}

	public String getDescModeloVersion() {
		return descModeloVersion;
	}

	public void setDescModeloVersion(String descModeloVersion) {
		this.descModeloVersion = descModeloVersion;
	}

	public Long getValPropio() {
		return valPropio;
	}

	public void setValPropio(Long valPropio) {
		this.valPropio = valPropio;
	}

	public Long getAnoAdquisicion() {
		return anoAdquisicion;
	}

	public void setAnoAdquisicion(Long anoAdquisicion) {
		this.anoAdquisicion = anoAdquisicion;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}
}
