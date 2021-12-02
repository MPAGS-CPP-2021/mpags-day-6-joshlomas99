#ifndef MPAGSCIPHER_EXCEPTIONS_HPP
#define MPAGSCIPHER_EXCEPTIONS_HPP

#include <iostream>
#include <string>
#include <exception>

/**
 * \file Exceptions.hpp
 * \brief Contains the declarations of custom exceptions.
 */

/**
 * \class MissingArgument
 * \brief Exception to handle missing arguments in processCommandLine function
 */
class MissingArgument : public std::invalid_argument {
    public:
        MissingArgument( const std::string& msg ) :
            std::invalid_argument(msg)
        {
        }
};

/**
 * \class UnknownArgument
 * \brief Exception to handle unknown arguments in processCommandLine function
 */
class UnknownArgument : public std::invalid_argument {
    public:
        UnknownArgument( const std::string& msg ) :
            std::invalid_argument(msg)
        {
        }
};

/**
 * \class InvalidKey
 * \brief Exception to handle invalid key input
 */
class InvalidKey : public std::invalid_argument {
    public:
        InvalidKey( const std::string& msg ) :
            std::invalid_argument(msg)
        {
        }
};

#endif    // MPAGSCIPHER_EXCEPTIONS_HPP