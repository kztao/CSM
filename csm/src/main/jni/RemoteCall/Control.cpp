//
// Created by wang.junren on 2018/9/28.
//

#include "Control.h"
#include "Export.h"

void Control::setFunctionParse(FunctionParse *functionParse) {
    this->functionParse = functionParse;
}

FunctionParse* Control::getFunctionParse() {
    return functionParse;
}