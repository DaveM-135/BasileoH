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
import javax.persistence.PrePersist;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotEmpty;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "RECURSOS_SKILLS")
public class Skill implements Serializable{

		private static final long serialVersionUID = 1L;
		
		@Id
		@GeneratedValue(strategy = GenerationType.IDENTITY)
		@Column(name = "cod_skill")
		private Long codSkill;
		
		@NotEmpty(message = "Este dato no debe estar vacío")
		@Column(name = "desc_skill_softskill")
		private String descSkill;
		
		@Column(name = "desc_tipo")
		private String descTipo;
		
		@Column(name = "desc_dominio_tecnico")
		private String descDominioTecnico;
		
		@Column(name = "val_ponderacion")
		private Long valPonderacion;
		
		@Column(name = "desc_comentario")
		private String descComentario;
	
		@Column(name = "fec_registro")
		@Temporal(TemporalType.TIMESTAMP)
		@DateTimeFormat(pattern = "yyyy-MM-dd hh:mm:ss")
		private Date fecRegistro;
		
		@PrePersist
		public void prePersist() {
			fecRegistro = new Date();
		}
		
		@ManyToOne(fetch = FetchType.LAZY)
		@JoinColumn(name = "cod_recurso")
		private Recurso recurso;

		public Long getCodSkill() {
			return codSkill;
		}

		public void setCodSkill(Long codSkill) {
			this.codSkill = codSkill;
		}

		public String getDescSkill() {
			return descSkill;
		}

		public void setDescSkill(String descSkill) {
			this.descSkill = descSkill;
		}

		public String getDescTipo() {
			return descTipo;
		}

		public void setDescTipo(String descTipo) {
			this.descTipo = descTipo;
		}

		public String getDescDominioTecnico() {
			return descDominioTecnico;
		}

		public void setDescDominioTecnico(String descDominioTecnico) {
			this.descDominioTecnico = descDominioTecnico;
		}

		public Long getValPonderacion() {
			return valPonderacion;
		}

		public void setValPonderacion(Long valPonderacion) {
			this.valPonderacion = valPonderacion;
		}

		public String getDescComentario() {
			return descComentario;
		}

		public void setDescComentario(String descComentario) {
			this.descComentario = descComentario;
		}

		public Date getFecRegistro() {
			return fecRegistro;
		}

		public void setFecRegistro(Date fecRegistro) {
			this.fecRegistro = fecRegistro;
		}

		public Recurso getRecurso() {
			return recurso;
		}

		public void setRecurso(Recurso recurso) {
			this.recurso = recurso;
		}

		public static long getSerialversionuid() {
			return serialVersionUID;
		}
		
		

}
