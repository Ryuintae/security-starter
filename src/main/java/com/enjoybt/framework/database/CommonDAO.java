package com.enjoybt.framework.database;

import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.dao.support.DaoSupport;
import org.springframework.util.Assert;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;

/**
 * DAO 기본 인터페이스
각 프로젝트에서 명시적으로 빈 등록 필요함
(org.mybatis.spring.SqlSessionFactoryBean 선언 필요) 

<bean name="commonDAO" class="com.enjoybt.common.dao.CommonDAO">
	<property name="sqlSessionFactory" ref="sqlSessionFactory"/>
</bean>
 */
public class CommonDAO extends DaoSupport {
	
	private SqlSession sqlSession;
	
    private boolean externalSqlSession;
    
    public final void setSqlSessionFactory(SqlSessionFactory sqlSessionFactory) {
        if (!this.externalSqlSession) {
            this.sqlSession = new SqlSessionTemplate(sqlSessionFactory);
        }
    }
    
    public final void setSqlSessionTemplate(SqlSessionTemplate sqlSessionTemplate) {
        this.sqlSession = sqlSessionTemplate;
        this.externalSqlSession = true;
    }
    
    public final SqlSession getSqlSession() {
        return this.sqlSession;
    }
    
    protected void checkDaoConfig() {
        Assert.notNull(this.sqlSession, "Property 'sqlSessionFactory' or 'sqlSessionTemplate' are required");
    }
    
    
    public Object selectObject(String mapperId) throws SQLException {
		return this.sqlSession.selectOne(mapperId);
	}
	
	public Object selectObject(String mapperId, Object parameter) throws SQLException {
		return this.sqlSession.selectOne(mapperId, parameter);
	}

	
	@SuppressWarnings("unchecked")
	public Map<String, Object> selectMap(String mapperId) throws SQLException {
		return (Map<String, Object>)this.sqlSession.selectOne(mapperId);
	}
	
	@SuppressWarnings("unchecked")
	public Map<String, Object> selectMap(String mapperId, Object parameter) throws SQLException {
		return (Map<String, Object>)this.sqlSession.selectOne(mapperId, parameter);
	}
	
	
	@SuppressWarnings("rawtypes")
	public List selectList(String mapperId) throws SQLException {
		return this.sqlSession.selectList(mapperId);
	}
	
	@SuppressWarnings("rawtypes")
	public List selectList(String mapperId, Object parameter) throws SQLException {
		return this.sqlSession.selectList(mapperId, parameter);
	}
	
	public int insert(String mapperId) throws SQLException {
		return this.sqlSession.insert(mapperId);
	}
	
	public int insert(String mapperId, Object parameter) throws SQLException {
		return this.sqlSession.insert(mapperId, parameter);
	}
	
	public int update(String mapperId) throws SQLException {
		return this.sqlSession.update(mapperId);
	}
	
	public int update(String mapperId, Object parameter) throws SQLException {
		return this.sqlSession.update(mapperId, parameter);
	}
	
	public int delete(String mapperId) throws SQLException {
		return this.sqlSession.delete(mapperId);
	}
	
	public int delete(String mapperId, Object parameter) throws SQLException {
		return this.sqlSession.delete(mapperId, parameter);
	}
}
