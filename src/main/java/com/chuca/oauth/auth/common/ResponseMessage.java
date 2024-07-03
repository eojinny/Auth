package com.chuca.oauth.auth.common;

public interface ResponseMessage {

    // http status 200
    String SUCCESS = "Success";

    // http status 400
    String VALIDATION_FAILED = "Validation failed";
    String DUPLICATE_EMAIL = "Duplicate_email";
    String DUPLICATE_NICKNAME = "DUPLICATE_NICKNAME";
    String DUPLICATE_TEL_NUMBER = "DUPLICATE_TEL_NUMBER";
    String NOT_EXISTED_USER = "NOT_EXISTED_USER";
    String NOT_EXISTED_BOARD = "NOT_EXISTED_BOARD";

    // http status 401
    String SIGN_IN_FAIL = "SIGN_IN_FAIL";
    String AUTHORIZATION_FAIL = "UTHORIZATION_FAIL";

    //http status 403
    String NO_PERMISSION = "NO_PERMISSION";

    //http status 500
    String DATABASE_ERROR = "DATABASE_ERROR";




}
