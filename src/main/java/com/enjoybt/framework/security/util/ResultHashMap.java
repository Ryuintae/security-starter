package com.enjoybt.framework.security.util;

import com.enjoybt.framework.config.Constants;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ResultHashMap extends HashMap<String, Object> {

    private static final long serialVersionUID = 1L;

    public void setSuccess() {
        this.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_SUCCESS);
    }

    public void setFailure() {
        this.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
    }


    public void setWrongAccess() {
        this.put(Constants.KEY_RESULT, Constants.VALUE_RESULT_FAILURE);
        this.put(Constants.KEY_MSG, Constants.VALUE_MSG_WRONG_ACCESS);
    }

    public void setList(List<?> list) {
        this.put(Constants.KEY_LIST, list);
    }

    public void setPaging(int totalCount, int page, int pageRow) {
        this.put(Constants.KEY_TOTAL_COUNT, totalCount);
        this.put(Constants.KEY_PAGE, page);
        this.put(Constants.KEY_PAGE_ROW, pageRow);
    }


    public void setData(Map<?, ?> data) {
        this.put(Constants.KEY_DATA, data);
    }

    public void setMessage(String message) {
        this.put(Constants.KEY_MSG, message);
    }

    public void reset() {
        this.clear();
    }
}
