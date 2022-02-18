package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.HistRespuestaAux;
import com.sophi.app.models.entity.HistoricoRespuestaClima;

public interface IHistoricoRespuestaClimaDao extends CrudRepository<HistoricoRespuestaClima, Long>{
	
//	@Query(value = "SELECT "+ 
//	"new com.sophi.app.models.entity.HistRespuestaAux(A.valRespuesta AS valRespuesta, A.valImagenRespuesta AS valImageRespuesta, B.iPreguntaRespuesta AS idPreguntaRespuesta, B.total AS total) " +
//	"FROM PreguntaRespuestaClima AS A LEFT JOIN "+
//	"(SELECT iPreguntaRespuesta, count(valConteoRespuesta) AS total " + 
//	"FROM HistoricoRespuestaClima " + 
//	"WHERE fecRespuesta BETWEEN ?1 and ?2 " +
//	"GROUP BY iPreguntaRespuesta) AS B ON A.valRespuesta = B.iPreguntaRespuesta ")
//	public List<HistRespuestaAux> resultados(Date fechaInicio, Date fechaFin);
	
//	@Query(nativeQuery = true, value="SELECT " +
	@Query(value="SELECT " +
			"new com.sophi.app.models.entity.HistRespuestaAux(iPreguntaRespuesta, count(iPreguntaRespuesta)) "+
			"FROM HistoricoRespuestaClima " + 
			"WHERE idDia = ?1 " + 
			"group by iPreguntaRespuesta ")
	public List<HistRespuestaAux> resultados(long idDia);
	
	@Query(value="SELECT COUNT(DISTINCT idRecurso) " +
			"FROM HistoricoRespuestaClima " + 
			"WHERE idDia = ?1 ")
	public Integer totalParticipacion(long idDia);
	
	
	
}
