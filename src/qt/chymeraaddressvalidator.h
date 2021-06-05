// Copyright (c) 2011-2020 The chymera Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef chymera_QT_chymeraADDRESSVALIDATOR_H
#define chymera_QT_chymeraADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class chymeraAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit chymeraAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

/** chymera address widget validator, checks for a valid chymera address.
 */
class chymeraAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit chymeraAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

#endif // chymera_QT_chymeraADDRESSVALIDATOR_H
